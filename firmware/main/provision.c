/*
 * USB provisioning console.
 *
 * Protocol: one JSON object per line from the host, e.g.
 *   {"id":1,"cmd":"info"}
 * The device answers with one line prefixed by "@@" so the host can skip any
 * interleaved log output:
 *   @@{"id":1,"ok":true,"result":{...}}
 *   @@{"id":1,"ok":false,"error":"..."}
 *
 * Only reachable after a physical BOOT press. WiFi and HTTPS are off here.
 */
#include "provision.h"
#include "bootloader_random.h"
#include "cJSON.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "eth_signer.h"
#include "hex.h"
#include "https_server.h"
#include "keccak256.h"
#include "led.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "policy.h"
#include "sdkconfig.h"
#include "signer_app.h"
#include "store.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "provision";

#define MAX_LINE (128 * 1024)

typedef struct {
    char err[200];
} cmd_ctx_t;

static cJSON *fail(cmd_ctx_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static cJSON *fail(cmd_ctx_t *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof(c->err), fmt, ap);
    va_end(ap);
    return NULL;
}

static void write_all(const char *s, size_t len)
{
    while (len) {
        int n = usb_serial_jtag_write_bytes(s, len, portMAX_DELAY);
        if (n <= 0) continue;
        s += n;
        len -= (size_t)n;
    }
}

static void reply(const cJSON *id, cJSON *result, const char *error)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddItemToObject(r, "id", id ? cJSON_Duplicate(id, 1) : cJSON_CreateNull());
    cJSON_AddBoolToObject(r, "ok", error == NULL);
    if (error)
        cJSON_AddStringToObject(r, "error", error);
    else
        cJSON_AddItemToObject(r, "result", result ? result : cJSON_CreateObject());
    char *s = cJSON_PrintUnformatted(r);
    /* The generate_key result carries the private key: wipe before freeing. */
    const cJSON *pk = result ? cJSON_GetObjectItemCaseSensitive(result, "private_key") : NULL;
    if (cJSON_IsString(pk)) eth_memzero(pk->valuestring, strlen(pk->valuestring));
    cJSON_Delete(r);
    if (!s) return;
    write_all("@@", 2);
    write_all(s, strlen(s));
    write_all("\n", 1);
    usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(1000));
    eth_memzero(s, strlen(s));
    cJSON_free(s);
}

static const char *get_str(const cJSON *req, const char *key)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(req, key);
    return cJSON_IsString(it) ? it->valuestring : NULL;
}

static bool get_bool(const cJSON *req, const char *key)
{
    return cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(req, key));
}

/* Base64-decode into a NUL-terminated heap buffer. */
static uint8_t *b64_decode(const char *in, size_t *out_len)
{
    size_t need = 0, inlen = strlen(in);
    int rc = mbedtls_base64_decode(NULL, 0, &need, (const unsigned char *)in, inlen);
    if (rc != 0 && rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return NULL;
    uint8_t *buf = malloc(need + 1);
    if (!buf) return NULL;
    if (mbedtls_base64_decode(buf, need, out_len, (const unsigned char *)in, inlen) != 0) {
        free(buf);
        return NULL;
    }
    buf[*out_len] = 0;
    return buf;
}

static int rng(void *ctx, unsigned char *buf, size_t len)
{
    esp_fill_random(buf, len);
    return 0;
}

/* -------------------------------------------------------------- commands */

static cJSON *cmd_info(const cJSON *req, cmd_ctx_t *c)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "firmware", esp_app_get_description()->version);
    cJSON_AddStringToObject(r, "mode", "provision");
    cJSON *p = cJSON_AddObjectToObject(r, "provisioned");
    bool key = signer_app_load_address() == ESP_OK;
    cJSON_AddBoolToObject(p, "key", key);
    cJSON_AddBoolToObject(p, "policy", store_has(STORE_KEY_POLICY));
    cJSON_AddBoolToObject(p, "wifi", store_has(STORE_KEY_WIFI_SSID));
    cJSON_AddBoolToObject(p, "tls", store_has(STORE_KEY_TLS_CERT) && store_has(STORE_KEY_TLS_KEY));
    cJSON_AddBoolToObject(p, "api_token", store_has(STORE_KEY_API_TOKEN_HASH));
    if (key) cJSON_AddStringToObject(r, "address", g_app.address_hex);

    char buf[72];
    if (store_get_str(STORE_KEY_HOSTNAME, buf, sizeof(buf)) != ESP_OK) strlcpy(buf, SIGNER_DEFAULT_HOSTNAME, sizeof(buf));
    cJSON_AddStringToObject(r, "hostname", buf);
    if (store_get_str(STORE_KEY_WIFI_SSID, buf, sizeof(buf)) == ESP_OK) cJSON_AddStringToObject(r, "wifi_ssid", buf);

    void *json = NULL;
    size_t len = 0;
    if (store_get_blob(STORE_KEY_POLICY, &json, &len) == ESP_OK) {
        char h[65];
        sha256_hex(json, len, h);
        cJSON_AddStringToObject(r, "policy_sha256", h);
        free(json);
    }
    return r;
}

static cJSON *key_result(void)
{
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "address", g_app.address_hex);
    return r;
}

static cJSON *cmd_generate_key(const cJSON *req, cmd_ctx_t *c)
{
    if (store_has(STORE_KEY_PRIVKEY) && !get_bool(req, "force"))
        return fail(c, "a key already exists; pass force=true to replace it (old key is lost unless backed up)");

    /* SAR-ADC entropy source: RF is off in provision mode, so enable it explicitly. */
    uint8_t ent[64], key[32];
    bootloader_random_enable();
    esp_fill_random(ent, sizeof(ent));
    bootloader_random_disable();
    do {
        keccak256(ent, sizeof(ent), key);
        ent[0]++;
    } while (!eth_privkey_valid(key));
    eth_memzero(ent, sizeof(ent));

    esp_err_t err = store_set_blob(STORE_KEY_PRIVKEY, key, 32);
    if (err != ESP_OK) {
        eth_memzero(key, sizeof(key));
        return fail(c, "store failed: %s", esp_err_to_name(err));
    }
    char hexkey[67] = "0x";
    hex_encode(key, 32, hexkey + 2);
    eth_memzero(key, sizeof(key));
    if (signer_app_load_address() != ESP_OK) return fail(c, "key derivation failed");

    cJSON *r = key_result();
    /* Returned ONCE so it can be backed up offline. */
    cJSON_AddStringToObject(r, "private_key", hexkey);
    eth_memzero(hexkey, sizeof(hexkey));
    ESP_LOGW(TAG, "new key generated: %s", g_app.address_hex);
    return r;
}

static cJSON *cmd_import_key(const cJSON *req, cmd_ctx_t *c)
{
    const char *hk = get_str(req, "private_key");
    if (!hk) return fail(c, "private_key required");
    if (store_has(STORE_KEY_PRIVKEY) && !get_bool(req, "force"))
        return fail(c, "a key already exists; pass force=true to replace it");
    uint8_t key[32];
    if (hex_decode(hk, key, 32) != 32 || !eth_privkey_valid(key)) {
        eth_memzero(key, sizeof(key));
        eth_memzero((char *)hk, strlen(hk));
        return fail(c, "invalid private key");
    }
    esp_err_t err = store_set_blob(STORE_KEY_PRIVKEY, key, 32);
    eth_memzero(key, sizeof(key));
    eth_memzero((char *)hk, strlen(hk));
    if (err != ESP_OK) return fail(c, "store failed: %s", esp_err_to_name(err));
    if (signer_app_load_address() != ESP_OK) return fail(c, "key derivation failed");
    ESP_LOGW(TAG, "key imported: %s", g_app.address_hex);
    return key_result();
}

static cJSON *cmd_set_policy(const cJSON *req, cmd_ctx_t *c)
{
    const char *b64 = get_str(req, "policy_b64");
    if (!b64) return fail(c, "policy_b64 required");
    size_t len;
    uint8_t *json = b64_decode(b64, &len);
    if (!json) return fail(c, "bad base64");
    bool has_key = signer_app_load_address() == ESP_OK;
    policy_t *p = NULL;
    char perr[160];
    if (policy_load((const char *)json, len, has_key ? g_app.address : NULL, &p, perr, sizeof(perr)) != 0) {
        free(json);
        return fail(c, "policy rejected: %s", perr);
    }
    size_t insts = policy_total_insts(p);
    policy_free(p);
    esp_err_t err = store_set_blob(STORE_KEY_POLICY, json, len);
    char h[65];
    sha256_hex(json, len, h);
    free(json);
    if (err != ESP_OK) return fail(c, "store failed: %s", esp_err_to_name(err));
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "policy_sha256", h);
    cJSON_AddNumberToObject(r, "regex_instructions", (double)insts);
    return r;
}

static cJSON *cmd_set_wifi(const cJSON *req, cmd_ctx_t *c)
{
    const char *ssid = get_str(req, "ssid"), *pass = get_str(req, "password");
    if (!ssid || !*ssid || strlen(ssid) > 32) return fail(c, "ssid must be 1..32 bytes");
    if (!pass) pass = "";
    if (strlen(pass) > 63) return fail(c, "password must be <= 63 bytes");
    if (store_set_str(STORE_KEY_WIFI_SSID, ssid) != ESP_OK || store_set_str(STORE_KEY_WIFI_PASS, pass) != ESP_OK)
        return fail(c, "store failed");
    return cJSON_CreateObject();
}

static bool valid_hostname(const char *h)
{
    size_t n = strlen(h);
    if (n < 1 || n > 63 || h[0] == '-' || h[n - 1] == '-') return false;
    for (size_t i = 0; i < n; i++)
        if (!(islower((unsigned char)h[i]) || isdigit((unsigned char)h[i]) || h[i] == '-')) return false;
    return true;
}

static cJSON *cmd_set_hostname(const cJSON *req, cmd_ctx_t *c)
{
    const char *h = get_str(req, "hostname");
    if (!h || !valid_hostname(h)) return fail(c, "hostname must match [a-z0-9-]{1,63} (no leading/trailing '-')");
    if (store_set_str(STORE_KEY_HOSTNAME, h) != ESP_OK) return fail(c, "store failed");
    return cJSON_CreateObject();
}

static cJSON *cmd_set_tls(const cJSON *req, cmd_ctx_t *c)
{
    const char *cb = get_str(req, "cert_pem_b64"), *kb = get_str(req, "key_pem_b64");
    if (!cb || !kb) return fail(c, "cert_pem_b64 and key_pem_b64 required");
    size_t clen, klen;
    uint8_t *cert = b64_decode(cb, &clen), *key = b64_decode(kb, &klen);
    cJSON *r = NULL;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&pk);
    if (!cert || !key) {
        r = fail(c, "bad base64");
        goto out;
    }
    int rc;
    if ((rc = mbedtls_x509_crt_parse(&crt, cert, clen + 1)) != 0) {
        r = fail(c, "certificate parse error -0x%04x", -rc);
        goto out;
    }
    if ((rc = mbedtls_pk_parse_key(&pk, key, klen + 1, NULL, 0, rng, NULL)) != 0) {
        r = fail(c, "private key parse error -0x%04x", -rc);
        goto out;
    }
    if ((rc = mbedtls_pk_check_pair(&crt.pk, &pk, rng, NULL)) != 0) {
        r = fail(c, "certificate and key do not match");
        goto out;
    }
    if (store_set_blob(STORE_KEY_TLS_CERT, cert, clen + 1) != ESP_OK ||
        store_set_blob(STORE_KEY_TLS_KEY, key, klen + 1) != ESP_OK) {
        r = fail(c, "store failed");
        goto out;
    }
    r = cJSON_CreateObject();
    char host[64], fqdn[80];
    if (store_get_str(STORE_KEY_HOSTNAME, host, sizeof(host)) != ESP_OK) strlcpy(host, SIGNER_DEFAULT_HOSTNAME, sizeof(host));
    snprintf(fqdn, sizeof(fqdn), "%s.local", host);
    bool san_ok = tls_cert_has_dns_name(&crt, fqdn);
    cJSON_AddBoolToObject(r, "san_matches_hostname", san_ok);
    if (!san_ok) cJSON_AddStringToObject(r, "warning", "certificate SAN does not contain <hostname>.local");
out:
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (key) {
        eth_memzero(key, klen);
        free(key);
    }
    free(cert);
    return r;
}

static cJSON *cmd_set_api_token(const cJSON *req, cmd_ctx_t *c)
{
    const char *t = get_str(req, "token");
    if (!t || strlen(t) < 32) return fail(c, "token must be at least 32 characters");
    if (strlen(t) > 256) return fail(c, "token too long");
    uint8_t h[32];
    sha256_raw(t, strlen(t), h);
    if (store_set_blob(STORE_KEY_API_TOKEN_HASH, h, 32) != ESP_OK) return fail(c, "store failed");
    return cJSON_CreateObject();
}

static cJSON *cmd_wipe(const cJSON *req, cmd_ctx_t *c)
{
    if (!get_bool(req, "confirm")) return fail(c, "pass confirm=true to erase key, policy and all settings");
    esp_err_t err = store_erase_all();
    if (err != ESP_OK) return fail(c, "erase failed: %s", esp_err_to_name(err));
    g_app.has_key = false;
    ESP_LOGW(TAG, "signer storage wiped");
    return cJSON_CreateObject();
}

typedef cJSON *(*handler_t)(const cJSON *req, cmd_ctx_t *c);
static const struct {
    const char *name;
    handler_t fn;
} CMDS[] = {
    {"info", cmd_info},
    {"generate_key", cmd_generate_key},
    {"import_key", cmd_import_key},
    {"set_policy", cmd_set_policy},
    {"set_wifi", cmd_set_wifi},
    {"set_hostname", cmd_set_hostname},
    {"set_tls", cmd_set_tls},
    {"set_api_token", cmd_set_api_token},
    {"wipe", cmd_wipe},
};

static void handle_line(char *line)
{
    cJSON *req = cJSON_Parse(line);
    if (!req) {
        reply(NULL, NULL, "invalid JSON");
        return;
    }
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(req, "id");
    const char *cmd = get_str(req, "cmd");
    if (!cmd) {
        reply(id, NULL, "cmd required");
    } else if (!strcmp(cmd, "reboot")) {
        reply(id, NULL, NULL);
        cJSON_Delete(req);
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_restart();
    } else {
        handler_t fn = NULL;
        for (size_t i = 0; i < sizeof(CMDS) / sizeof(CMDS[0]); i++)
            if (!strcmp(cmd, CMDS[i].name)) fn = CMDS[i].fn;
        if (!fn) {
            reply(id, NULL, "unknown cmd");
        } else {
            cmd_ctx_t c = {0};
            cJSON *r = fn(req, &c);
            reply(id, r, r ? NULL : c.err);
        }
    }
    /* Wipe request buffers that may have carried secrets. */
    cJSON_Delete(req);
}

void provision_run(void)
{
    led_set(LED_PROVISION);
    esp_log_level_set("*", ESP_LOG_WARN);

    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 4096;
    cfg.tx_buffer_size = 4096;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));
    usb_serial_jtag_vfs_use_driver();

    ESP_LOGW(TAG, "PROVISION MODE (fw %s). Timeout %d s.", esp_app_get_description()->version,
             CONFIG_SIGNER_PROVISION_TIMEOUT_S);
    signer_app_load_address();

    char *line = malloc(MAX_LINE + 1);
    if (!line) esp_restart();
    size_t len = 0;
    bool overflow = false;
    int64_t last = esp_timer_get_time();
    uint8_t chunk[512];

    for (;;) {
        int n = usb_serial_jtag_read_bytes(chunk, sizeof(chunk), pdMS_TO_TICKS(500));
        int64_t now = esp_timer_get_time();
        if (n <= 0) {
            if (now - last > (int64_t)CONFIG_SIGNER_PROVISION_TIMEOUT_S * 1000000) {
                ESP_LOGW(TAG, "provision timeout, rebooting");
                eth_memzero(line, MAX_LINE + 1);
                esp_restart();
            }
            continue;
        }
        last = now;
        for (int i = 0; i < n; i++) {
            char ch = (char)chunk[i];
            if (ch == '\r') continue;
            if (ch == '\n') {
                if (overflow) {
                    reply(NULL, NULL, "line too long");
                } else if (len) {
                    line[len] = 0;
                    handle_line(line);
                }
                eth_memzero(line, len);
                len = 0;
                overflow = false;
                continue;
            }
            if (len < MAX_LINE)
                line[len++] = ch;
            else
                overflow = true;
        }
        eth_memzero(chunk, sizeof(chunk));
    }
}
