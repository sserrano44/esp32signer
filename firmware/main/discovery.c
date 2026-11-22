#include "discovery.h"
#include "esp_app_desc.h"
#include "esp_log.h"
#include "mdns.h"

static const char *TAG = "mdns";

esp_err_t discovery_start(const char *hostname, const char *address_hex, int port)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mdns_init: %s", esp_err_to_name(err));
        return err;
    }
    mdns_hostname_set(hostname);
    mdns_instance_name_set("ESP32 Signer");
    mdns_txt_item_t txt[] = {
        {"path", "/"},
        {"fw", esp_app_get_description()->version},
        {"addr", address_hex},
    };
    err = mdns_service_add(NULL, "_https", "_tcp", (uint16_t)port, txt, sizeof(txt) / sizeof(txt[0]));
    if (err != ESP_OK) ESP_LOGE(TAG, "mdns_service_add: %s", esp_err_to_name(err));
    else ESP_LOGI(TAG, "advertising %s.local (_https._tcp:%d)", hostname, port);
    return err;
}
