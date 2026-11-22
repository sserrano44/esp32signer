#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* All secrets and configuration live in the dedicated "signer_nvs" partition,
 * namespace "signer". With CONFIG_NVS_ENCRYPTION (release build) the
 * partition is encrypted with keys protected by the eFuse HMAC key. */

#define STORE_KEY_PRIVKEY "privkey"
#define STORE_KEY_POLICY "policy"
#define STORE_KEY_WIFI_SSID "wifi_ssid"
#define STORE_KEY_WIFI_PASS "wifi_pass"
#define STORE_KEY_HOSTNAME "hostname"
#define STORE_KEY_TLS_CERT "tls_cert"
#define STORE_KEY_TLS_KEY "tls_key"
#define STORE_KEY_API_TOKEN_HASH "api_tok_hash"

esp_err_t store_init(void);
bool store_has(const char *key);
/* Allocates *out (caller frees with free(); zero secrets first). For blobs
 * stored with a trailing NUL (PEM, JSON), *len includes it. */
esp_err_t store_get_blob(const char *key, void **out, size_t *len);
esp_err_t store_set_blob(const char *key, const void *data, size_t len);
esp_err_t store_get_str(const char *key, char *buf, size_t cap);
esp_err_t store_set_str(const char *key, const char *val);
esp_err_t store_get_fixed(const char *key, void *buf, size_t len);
esp_err_t store_erase_key(const char *key);
esp_err_t store_erase_all(void);

#ifdef __cplusplus
}
#endif
