#include "eth_signer.h"
#include "keccak256.h"
#include "secp256k1.h"
#include "secp256k1_recovery.h"
#include <string.h>

static secp256k1_context *s_ctx;

void eth_memzero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int eth_signer_init(const uint8_t seed[32])
{
    if (s_ctx) return 0;
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!s_ctx) return -1;
    if (!secp256k1_context_randomize(s_ctx, seed)) {
        secp256k1_context_destroy(s_ctx);
        s_ctx = NULL;
        return -1;
    }
    return 0;
}

void eth_signer_deinit(void)
{
    if (s_ctx) secp256k1_context_destroy(s_ctx);
    s_ctx = NULL;
}

int eth_privkey_valid(const uint8_t key[32])
{
    return secp256k1_ec_seckey_verify(secp256k1_context_static, key) == 1;
}

int eth_address_from_privkey(const uint8_t key[32], uint8_t addr[20])
{
    if (!s_ctx) return -1;
    secp256k1_pubkey pub;
    uint8_t ser[65], h[32];
    size_t len = sizeof(ser);
    if (!secp256k1_ec_pubkey_create(s_ctx, &pub, key)) return -1;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, ser, &len, &pub, SECP256K1_EC_UNCOMPRESSED);
    keccak256(ser + 1, 64, h);
    memcpy(addr, h + 12, 20);
    return 0;
}

int eth_sign_hash(const uint8_t key[32], const uint8_t hash[32], uint8_t r[32], uint8_t s[32], int *recid)
{
    if (!s_ctx) return -1;
    secp256k1_ecdsa_recoverable_signature sig;
    uint8_t rs[64];
    /* secp256k1_ecdsa_sign_recoverable uses RFC6979 and always produces low-s. */
    if (!secp256k1_ecdsa_sign_recoverable(s_ctx, &sig, hash, key, NULL, NULL)) return -1;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_static, rs, recid, &sig);
    memcpy(r, rs, 32);
    memcpy(s, rs + 32, 32);
    eth_memzero(&sig, sizeof(sig));
    return 0;
}

int eth_tx_sign(const eth_tx_t *tx, const uint8_t key[32], uint8_t *out, size_t cap, size_t *out_len,
                uint8_t txhash[32])
{
    uint8_t h[32], r[32], s[32];
    int recid = 0;
    size_t plen = 0;
    /* Build the unsigned payload in `out` (saves a ~22 KB heap buffer on-device). */
    if (eth_tx_signing_payload(tx, out, cap, &plen) != 0) return -1;
    keccak256(out, plen, h);
    if (eth_sign_hash(key, h, r, s, &recid) != 0) return -1;
    if (eth_tx_encode_signed(tx, recid, r, s, out, cap, out_len) != 0) return -1;
    keccak256(out, *out_len, txhash);
    return 0;
}
