#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int hex_nibble(char c);

/* Decode hex (optional 0x prefix, even number of digits). Returns number of
 * bytes written, or -1 on bad input / insufficient capacity. */
int hex_decode(const char *s, uint8_t *out, size_t out_cap);

/* Lowercase hex, no prefix, NUL terminated. `out` must hold 2*len+1 bytes. */
void hex_encode(const uint8_t *in, size_t len, char *out);

/* Fixed-width 256-bit big-endian unsigned integers. */
typedef uint8_t u256_t[32];

/* "0x..." quantity -> u256. Leading zeros tolerated. Returns 0 on success. */
int u256_from_hex(const char *s, uint8_t out[32]);
/* Decimal string -> u256. Returns 0 on success, -1 on overflow / bad char. */
int u256_from_dec(const char *s, uint8_t out[32]);
void u256_from_u64(uint64_t v, uint8_t out[32]);
/* Returns 0 if value fits in u64. */
int u256_to_u64(const uint8_t v[32], uint64_t *out);
int u256_cmp(const uint8_t a[32], const uint8_t b[32]);
int u256_is_zero(const uint8_t v[32]);
/* Decimal representation; out must hold 79 bytes. */
void u256_to_dec(const uint8_t v[32], char *out);

/* 0x-prefixed 20-byte address (any case). Returns 0 on success. */
int addr_from_hex(const char *s, uint8_t out[20]);
/* 0x + lowercase hex, out must hold 43 bytes. */
void addr_to_hex(const uint8_t a[20], char *out);
/* EIP-55 checksum form, out must hold 43 bytes. */
void addr_to_checksum_hex(const uint8_t a[20], char *out);

#ifdef __cplusplus
}
#endif
