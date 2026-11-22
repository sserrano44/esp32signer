#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>

esp_err_t wifi_start(const char *ssid, const char *pass, const char *hostname);
bool wifi_wait_connected(uint32_t timeout_ms);
void wifi_get_ip(char *buf, size_t cap);
