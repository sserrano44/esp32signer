#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t st[25];
    size_t pos; /* bytes absorbed into current block */
} keccak256_ctx_t;

void keccak256_init(keccak256_ctx_t *ctx);
void keccak256_update(keccak256_ctx_t *ctx, const uint8_t *data, size_t len);
void keccak256_final(keccak256_ctx_t *ctx, uint8_t out[32]);

/* One-shot Ethereum keccak256 (original Keccak padding 0x01, not SHA3-256). */
void keccak256(const uint8_t *data, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
