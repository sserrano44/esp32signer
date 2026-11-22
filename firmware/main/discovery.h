#pragma once
#include "esp_err.h"

/* Bonjour/mDNS: answer for <hostname>.local and advertise _https._tcp. */
esp_err_t discovery_start(const char *hostname, const char *address_hex, int port);
