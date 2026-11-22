#pragma once
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "policy.h"
#include <stdbool.h>
#include <stdint.h>

#define SIGNER_DEFAULT_HOSTNAME "signer"

typedef struct {
    bool has_key;
    uint8_t address[20];
    char address_hex[43]; /* EIP-55 */
    policy_t *policy;
    char policy_hash[65];
    uint8_t token_hash[32];
    char hostname[64];
    uint32_t n_signed;
    uint32_t n_rejected;
    uint32_t n_auth_fail;
    SemaphoreHandle_t lock;
} signer_app_t;

extern signer_app_t g_app;

/* Persist a flag in RTC memory and reboot into provision mode. */
void signer_app_request_provision(void) __attribute__((noreturn));
/* True (once) if the previous boot requested provision mode. */
bool signer_app_take_provision_flag(void);

/* Initialise the secp256k1 context (blinded with hardware RNG). */
esp_err_t signer_app_crypto_init(void);
/* Derive address from the stored key (key is wiped from RAM afterwards). */
esp_err_t signer_app_load_address(void);
/* Load everything needed for signer mode. On failure `err` names what's missing. */
esp_err_t signer_app_load(char *err, size_t errlen);

void sha256_hex(const void *data, size_t len, char out[65]);
void sha256_raw(const void *data, size_t len, uint8_t out[32]);
