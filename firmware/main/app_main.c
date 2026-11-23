/*
 * ESP32-S3 policy-enforcing Ethereum signer.
 *
 * Boot flow:
 *   1. If the previous boot requested it (runtime long-press), or BOOT is
 *      pressed during the boot window (LED blinking white) -> provision mode
 *      (USB console only, WiFi off).
 *   2. Otherwise -> signer mode: WiFi + mDNS + HTTPS JSON-RPC
 *      (eth_signTransaction), enforcing the stored policy.
 */
#include "button.h"
#include "discovery.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "https_server.h"
#include "led.h"
#include "mbedtls/x509_crt.h"
#include "nvs_flash.h"
#include "provision.h"
#include "sdkconfig.h"
#include "signer_app.h"
#include "store.h"
#include "wifi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "main";

static void check_cert_san(const char *pem, size_t len, const char *hostname)
{
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    char fqdn[80];
    snprintf(fqdn, sizeof(fqdn), "%s.local", hostname);
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)pem, len) == 0 && !tls_cert_has_dns_name(&crt, fqdn))
        ESP_LOGW(TAG, "TLS certificate SAN does not include %s; clients will fail hostname verification", fqdn);
    mbedtls_x509_crt_free(&crt);
}

static void halt_with_error(const char *msg)
{
    ESP_LOGE(TAG, "%s", msg);
    ESP_LOGE(TAG, "hold BOOT for %d ms to enter provision mode", CONFIG_SIGNER_LONG_PRESS_MS);
    led_set(LED_ERROR);
    /* Return from app_main; LED + long-press tasks keep running. */
}

void app_main(void)
{
    led_init();
    button_init();
    ESP_LOGI(TAG, "esp32signer %s", esp_app_get_description()->version);

    /* Default NVS is used only by the WiFi/PHY stack. */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    /* On failure, keep going as far as provision mode, where `wipe` is the
     * explicit (physically gated) recovery; the partition is never erased
     * automatically. */
    esp_err_t store_err = store_init();
    if (signer_app_crypto_init() != ESP_OK) {
        halt_with_error("secp256k1 init failed");
        return;
    }

    bool provision = signer_app_take_provision_flag();
    if (!provision) {
        led_set(LED_BOOT_WINDOW);
        provision = button_wait_press(CONFIG_SIGNER_BOOT_WINDOW_MS);
    }
    if (provision) provision_run(); /* never returns */

    button_watch_long_press(CONFIG_SIGNER_LONG_PRESS_MS, signer_app_request_provision);
    if (store_err != ESP_OK) {
        halt_with_error("signer storage unreadable; not erased. Reflash the previous firmware, or enter "
                        "provision mode and run `esp32signer wipe` (destroys the key)");
        return;
    }

    char msg[200];
    if (signer_app_load(msg, sizeof(msg)) != ESP_OK) {
        halt_with_error(msg);
        return;
    }

    char ssid[33] = "", pass[64] = "";
    store_get_str(STORE_KEY_WIFI_SSID, ssid, sizeof(ssid));
    store_get_str(STORE_KEY_WIFI_PASS, pass, sizeof(pass));
    wifi_start(ssid, pass, g_app.hostname);
    memset(pass, 0, sizeof(pass));

    /* Cert and key stay in RAM for the server's lifetime. */
    void *cert = NULL, *key = NULL;
    size_t cert_len = 0, key_len = 0;
    if (store_get_blob(STORE_KEY_TLS_CERT, &cert, &cert_len) != ESP_OK ||
        store_get_blob(STORE_KEY_TLS_KEY, &key, &key_len) != ESP_OK) {
        halt_with_error("cannot read TLS material");
        return;
    }
    check_cert_san(cert, cert_len, g_app.hostname);

    discovery_start(g_app.hostname, g_app.address_hex, CONFIG_SIGNER_HTTPS_PORT);
    if (!wifi_wait_connected(30000)) ESP_LOGW(TAG, "WiFi not connected yet, still trying in background");

    if (https_server_start(cert, cert_len, key, key_len) != ESP_OK) {
        halt_with_error("HTTPS server failed to start");
        return;
    }
    char ip[16];
    wifi_get_ip(ip, sizeof(ip));
    ESP_LOGI(TAG, "ready: https://%s.local/ (%s) signer %s", g_app.hostname, ip, g_app.address_hex);
}
