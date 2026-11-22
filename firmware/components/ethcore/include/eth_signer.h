#pragma once
#include "eth_tx.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Create the secp256k1 context and blind it with 32 random bytes. */
int eth_signer_init(const uint8_t seed[32]);
void eth_signer_deinit(void);

/* 1 if 0 < k < n. */
int eth_privkey_valid(const uint8_t key[32]);
int eth_address_from_privkey(const uint8_t key[32], uint8_t addr[20]);

/* RFC6979 deterministic, low-s, recoverable signature over a 32-byte hash. */
int eth_sign_hash(const uint8_t key[32], const uint8_t hash[32], uint8_t r[32], uint8_t s[32], int *recid);

/* Hash, sign and serialize a transaction. Writes the raw signed tx to `out`
 * and its keccak hash (the tx hash) to `txhash`. */
int eth_tx_sign(const eth_tx_t *tx, const uint8_t key[32], uint8_t *out, size_t cap, size_t *out_len,
                uint8_t txhash[32]);

/* Best-effort wipe that the compiler will not optimize away. */
void eth_memzero(void *p, size_t n);

#ifdef __cplusplus
}
#endif
