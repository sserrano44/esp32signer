#include "https_server.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/asn1.h"
#include "rpc.h"
#include "sdkconfig.h"
#include "signer_app.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "https";

#define AUTH_FREE_FAILURES 10
#define AUTH_MAX_BACKOFF_S 30

static uint32_t s_consecutive_auth_fail;

bool tls_cert_has_dns_name(const mbedtls_x509_crt *crt, const char *dns)
{
    size_t dl = strlen(dns);
    for (const mbedtls_x509_sequence *cur = &crt->subject_alt_names; cur && cur->buf.p; cur = cur->next) {
        if (cur->buf.tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME)) continue;
        if (cur->buf.len == dl && !strncasecmp((const char *)cur->buf.p, dns, dl)) return true;
    }
    return false;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static bool authorized(httpd_req_t *req)
{
    char hdr[300];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK) return false;
    if (strncasecmp(hdr, "Bearer ", 7) != 0) return false;
    const char *tok = hdr + 7;
    uint8_t h[32];
    sha256_raw(tok, strlen(tok), h);
    memset(hdr, 0, sizeof(hdr));
    return ct_equal(h, g_app.token_hash, 32);
}

static esp_err_t send_json(httpd_req_t *req, const char *status, const char *body)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t rpc_post(httpd_req_t *req)
{
    if (!authorized(req)) {
        uint32_t n = ++s_consecutive_auth_fail;
        g_app.n_auth_fail++;
        if (n > AUTH_FREE_FAILURES) {
            uint32_t delay = n - AUTH_FREE_FAILURES;
            if (delay > AUTH_MAX_BACKOFF_S) delay = AUTH_MAX_BACKOFF_S;
            ESP_LOGW(TAG, "auth failure #%u, backing off %u s", (unsigned)n, (unsigned)delay);
            vTaskDelay(pdMS_TO_TICKS(delay * 1000));
        } else {
            ESP_LOGW(TAG, "auth failure #%u", (unsigned)n);
        }
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Bearer");
        return send_json(req, "401 Unauthorized", "{\"error\":\"unauthorized\"}");
    }
    s_consecutive_auth_fail = 0;

    size_t total = req->content_len;
    if (total == 0) return send_json(req, "400 Bad Request", "{\"error\":\"empty body\"}");
    if (total > CONFIG_SIGNER_MAX_BODY) return send_json(req, "413 Payload Too Large", "{\"error\":\"body too large\"}");

    char *body = malloc(total + 1);
    if (!body) return send_json(req, "503 Service Unavailable", "{\"error\":\"out of memory\"}");
    size_t got = 0;
    int retries = 0;
    while (got < total) {
        int n = httpd_req_recv(req, body + got, total - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT && ++retries < 3) continue;
        if (n <= 0) {
            free(body);
            return ESP_FAIL; /* closes the socket */
        }
        got += (size_t)n;
    }
    body[total] = 0;

    char *resp = rpc_handle(body, total);
    free(body);
    if (!resp) return send_json(req, "500 Internal Server Error", "{\"error\":\"internal error\"}");
    esp_err_t err = send_json(req, "200 OK", resp);
    free(resp);
    return err;
}

esp_err_t https_server_start(const char *cert_pem, size_t cert_len, const char *key_pem, size_t key_len)
{
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t *)cert_pem;
    conf.servercert_len = cert_len;
    conf.prvtkey_pem = (const uint8_t *)key_pem;
    conf.prvtkey_len = key_len;
    conf.port_secure = CONFIG_SIGNER_HTTPS_PORT;
    conf.httpd.max_open_sockets = 3; /* each TLS session costs RAM */
    conf.httpd.lru_purge_enable = true;
    conf.httpd.stack_size = 12288;   /* JSON + policy + secp256k1 run in this task */
    conf.httpd.core_id = 1;          /* keep WiFi on core 0 */
    conf.httpd.max_uri_handlers = 2;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ssl_start failed: %s", esp_err_to_name(err));
        return err;
    }
    const httpd_uri_t post = {.uri = "/", .method = HTTP_POST, .handler = rpc_post};
    httpd_register_uri_handler(server, &post);
    ESP_LOGI(TAG, "JSON-RPC listening on https://%s.local:%d/", g_app.hostname, CONFIG_SIGNER_HTTPS_PORT);
    return ESP_OK;
}
