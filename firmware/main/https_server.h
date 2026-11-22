#pragma once
#include "esp_err.h"
#include "mbedtls/x509_crt.h"
#include <stdbool.h>
#include <stddef.h>

/* Start the HTTPS JSON-RPC server on CONFIG_SIGNER_HTTPS_PORT. PEM buffers
 * must include the trailing NUL and stay alive for the server's lifetime. */
esp_err_t https_server_start(const char *cert_pem, size_t cert_len, const char *key_pem, size_t key_len);

/* True if the certificate has a SAN dNSName equal to `dns` (case-insensitive). */
bool tls_cert_has_dns_name(const mbedtls_x509_crt *crt, const char *dns);
