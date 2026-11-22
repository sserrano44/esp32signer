#include "store.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include <stdlib.h>
#include <string.h>

#define PARTITION "signer_nvs"
#define NAMESPACE "signer"

static const char *TAG __attribute__((unused)) = "store";

esp_err_t store_init(void)
{
    esp_err_t err;
#if CONFIG_NVS_ENCRYPTION
    nvs_sec_scheme_t *scheme = nvs_flash_get_default_security_scheme();
    if (!scheme) {
        ESP_LOGE(TAG, "no NVS security scheme registered");
        return ESP_FAIL;
    }
    nvs_sec_cfg_t cfg;
    err = nvs_flash_read_security_cfg_v2(scheme, &cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "generating NVS encryption keys (%s)", esp_err_to_name(err));
        err = nvs_flash_generate_keys_v2(scheme, &cfg);
        if (err != ESP_OK) return err;
    }
    err = nvs_flash_secure_init_partition(PARTITION, &cfg);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase_partition(PARTITION));
        err = nvs_flash_secure_init_partition(PARTITION, &cfg);
    }
    memset(&cfg, 0, sizeof(cfg));
#else
    err = nvs_flash_init_partition(PARTITION);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase_partition(PARTITION));
        err = nvs_flash_init_partition(PARTITION);
    }
#endif
    return err;
}

static esp_err_t open_ns(nvs_open_mode_t mode, nvs_handle_t *h)
{
    return nvs_open_from_partition(PARTITION, NAMESPACE, mode, h);
}

bool store_has(const char *key)
{
    nvs_handle_t h;
    if (open_ns(NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = 0;
    esp_err_t err = nvs_get_blob(h, key, NULL, &len);
    if (err == ESP_ERR_NVS_TYPE_MISMATCH || err == ESP_ERR_NVS_NOT_FOUND) err = nvs_get_str(h, key, NULL, &len);
    nvs_close(h);
    return err == ESP_OK && len > 0;
}

esp_err_t store_get_blob(const char *key, void **out, size_t *len)
{
    nvs_handle_t h;
    *out = NULL;
    *len = 0;
    esp_err_t err = open_ns(NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t n = 0;
    err = nvs_get_blob(h, key, NULL, &n);
    if (err == ESP_OK) {
        void *buf = malloc(n ? n : 1);
        if (!buf) {
            err = ESP_ERR_NO_MEM;
        } else if ((err = nvs_get_blob(h, key, buf, &n)) == ESP_OK) {
            *out = buf;
            *len = n;
        } else {
            free(buf);
        }
    }
    nvs_close(h);
    return err;
}

esp_err_t store_get_fixed(const char *key, void *buf, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t n = len;
    err = nvs_get_blob(h, key, buf, &n);
    nvs_close(h);
    if (err == ESP_OK && n != len) err = ESP_ERR_INVALID_SIZE;
    return err;
}

esp_err_t store_set_blob(const char *key, const void *data, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, data, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t store_get_str(const char *key, char *buf, size_t cap)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t n = cap;
    err = nvs_get_str(h, key, buf, &n);
    nvs_close(h);
    return err;
}

esp_err_t store_set_str(const char *key, const char *val)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, key, val);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t store_erase_key(const char *key)
{
    nvs_handle_t h;
    esp_err_t err = open_ns(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_key(h, key);
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t store_erase_all(void)
{
    /* nvs_erase_all() only marks entries as erased; the old key bytes could
     * remain in flash. Physically erase every sector of the partition. */
    nvs_flash_deinit_partition(PARTITION);
    esp_err_t err = nvs_flash_erase_partition(PARTITION);
    if (err != ESP_OK) return err;
    return store_init();
}
