#include "signer_app.h"
#include "bootloader_random.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "eth_signer.h"
#include "hex.h"
#include "mbedtls/sha256.h"
#include "store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "app";

#define PROVISION_MAGIC 0x50524f56u /* "PROV" */
static RTC_NOINIT_ATTR uint32_t s_provision_magic;

signer_app_t g_app;

void signer_app_request_provision(void)
{
    s_provision_magic = PROVISION_MAGIC;
    esp_restart();
}

bool signer_app_take_provision_flag(void)
{
    bool set = s_provision_magic == PROVISION_MAGIC;
    s_provision_magic = 0;
    return set;
}

void sha256_raw(const void *data, size_t len, uint8_t out[32])
{
    mbedtls_sha256(data, len, out, 0);
}

void sha256_hex(const void *data, size_t len, char out[65])
{
    uint8_t h[32];
    sha256_raw(data, len, h);
    hex_encode(h, 32, out);
}

esp_err_t signer_app_crypto_init(void)
{
    uint8_t seed[32];
    /* RF is not up yet: enable the SAR-ADC entropy source explicitly. */
    bootloader_random_enable();
    esp_fill_random(seed, sizeof(seed));
    bootloader_random_disable();
    int rc = eth_signer_init(seed);
    eth_memzero(seed, sizeof(seed));
    if (rc != 0) return ESP_FAIL;
    if (!g_app.lock) g_app.lock = xSemaphoreCreateMutex();
    return g_app.lock ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t signer_app_load_address(void)
{
    uint8_t key[32];
    g_app.has_key = false;
    if (store_get_fixed(STORE_KEY_PRIVKEY, key, 32) != ESP_OK) return ESP_ERR_NOT_FOUND;
    int ok = eth_privkey_valid(key) && eth_address_from_privkey(key, g_app.address) == 0;
    eth_memzero(key, sizeof(key));
    if (!ok) return ESP_ERR_INVALID_STATE;
    addr_to_checksum_hex(g_app.address, g_app.address_hex);
    g_app.has_key = true;
    return ESP_OK;
}

esp_err_t signer_app_load(char *err, size_t errlen)
{
    if (store_has(STORE_KEY_PROV_DIRTY)) {
        snprintf(err, errlen, "provisioning was interrupted (no commit): provision again");
        return ESP_ERR_INVALID_STATE;
    }
    char missing[96] = "";
    if (signer_app_load_address() != ESP_OK) strlcat(missing, " key", sizeof(missing));
    if (!store_has(STORE_KEY_POLICY)) strlcat(missing, " policy", sizeof(missing));
    if (!store_has(STORE_KEY_WIFI_SSID)) strlcat(missing, " wifi", sizeof(missing));
    if (!store_has(STORE_KEY_TLS_CERT) || !store_has(STORE_KEY_TLS_KEY)) strlcat(missing, " tls", sizeof(missing));
    if (store_get_fixed(STORE_KEY_API_TOKEN_HASH, g_app.token_hash, 32) != ESP_OK)
        strlcat(missing, " api_token", sizeof(missing));
    if (missing[0]) {
        snprintf(err, errlen, "not provisioned, missing:%s", missing);
        return ESP_ERR_NOT_FOUND;
    }

    if (store_get_str(STORE_KEY_HOSTNAME, g_app.hostname, sizeof(g_app.hostname)) != ESP_OK)
        strlcpy(g_app.hostname, SIGNER_DEFAULT_HOSTNAME, sizeof(g_app.hostname));

    void *json = NULL;
    size_t len = 0;
    if (store_get_blob(STORE_KEY_POLICY, &json, &len) != ESP_OK) {
        snprintf(err, errlen, "cannot read policy");
        return ESP_FAIL;
    }
    sha256_hex(json, len, g_app.policy_hash);
    char perr[160];
    policy_t *p = NULL;
    int rc = policy_load(json, len, g_app.address, &p, perr, sizeof(perr));
    free(json);
    if (rc != 0) {
        snprintf(err, errlen, "stored policy invalid: %s", perr);
        return ESP_FAIL;
    }
    g_app.policy = p;
    ESP_LOGI(TAG, "address %s, policy %.16s… (%u regex insts)", g_app.address_hex, g_app.policy_hash,
             (unsigned)policy_total_insts(p));
    return ESP_OK;
}
