#include "eth_tx.h"
#include "keccak256.h"
#include "rlp.h"
#include <stdlib.h>
#include <string.h>

static void put_access_list(rlp_buf_t *r, const eth_tx_t *tx)
{
    size_t outer = rlp_list_begin(r);
    for (size_t i = 0; i < tx->al_count; i++) {
        const eth_al_entry_t *e = &tx->al[i];
        size_t item = rlp_list_begin(r);
        rlp_put_bytes(r, e->addr, 20);
        size_t keys = rlp_list_begin(r);
        for (size_t k = 0; k < e->key_count; k++) rlp_put_bytes(r, tx->al_keys[e->key_start + k], 32);
        rlp_list_end(r, keys);
        rlp_list_end(r, item);
    }
    rlp_list_end(r, outer);
}

static void put_to(rlp_buf_t *r, const eth_tx_t *tx)
{
    if (tx->has_to)
        rlp_put_bytes(r, tx->to, 20);
    else
        rlp_put_bytes(r, NULL, 0);
}

/* Fields common to signing payload and signed tx; sig == NULL for unsigned. */
static int encode(const eth_tx_t *tx, int recid, const uint8_t *r32, const uint8_t *s32, uint8_t *out,
                  size_t cap, size_t *out_len)
{
    rlp_buf_t r;
    if (tx->type == ETH_TX_TYPE_EIP1559) {
        if (cap < 1) return -1;
        out[0] = 0x02;
        rlp_init(&r, out + 1, cap - 1);
        size_t l = rlp_list_begin(&r);
        rlp_put_u64(&r, tx->chain_id);
        rlp_put_u64(&r, tx->nonce);
        rlp_put_uint_be(&r, tx->max_prio, 32);
        rlp_put_uint_be(&r, tx->max_fee, 32);
        rlp_put_u64(&r, tx->gas);
        put_to(&r, tx);
        rlp_put_uint_be(&r, tx->value, 32);
        rlp_put_bytes(&r, tx->data, tx->data_len);
        put_access_list(&r, tx);
        if (r32) {
            rlp_put_u64(&r, (uint64_t)recid);
            rlp_put_uint_be(&r, r32, 32);
            rlp_put_uint_be(&r, s32, 32);
        }
        rlp_list_end(&r, l);
        if (r.err) return -1;
        *out_len = r.len + 1;
        return 0;
    }
    if (tx->type == ETH_TX_TYPE_LEGACY) {
        rlp_init(&r, out, cap);
        size_t l = rlp_list_begin(&r);
        rlp_put_u64(&r, tx->nonce);
        rlp_put_uint_be(&r, tx->gas_price, 32);
        rlp_put_u64(&r, tx->gas);
        put_to(&r, tx);
        rlp_put_uint_be(&r, tx->value, 32);
        rlp_put_bytes(&r, tx->data, tx->data_len);
        if (r32) {
            /* EIP-155: v = chainId * 2 + 35 + recid. chain_id is bounded on parse. */
            rlp_put_u64(&r, tx->chain_id * 2 + 35 + (uint64_t)recid);
            rlp_put_uint_be(&r, r32, 32);
            rlp_put_uint_be(&r, s32, 32);
        } else {
            rlp_put_u64(&r, tx->chain_id);
            rlp_put_bytes(&r, NULL, 0);
            rlp_put_bytes(&r, NULL, 0);
        }
        rlp_list_end(&r, l);
        if (r.err) return -1;
        *out_len = r.len;
        return 0;
    }
    return -1;
}

int eth_tx_signing_payload(const eth_tx_t *tx, uint8_t *out, size_t cap, size_t *out_len)
{
    return encode(tx, 0, NULL, NULL, out, cap, out_len);
}

int eth_tx_signing_hash(const eth_tx_t *tx, uint8_t hash[32])
{
    uint8_t *buf = malloc(ETH_TX_MAX_ENCODED);
    if (!buf) return -1;
    size_t len = 0;
    int rc = eth_tx_signing_payload(tx, buf, ETH_TX_MAX_ENCODED, &len);
    if (rc == 0) keccak256(buf, len, hash);
    free(buf);
    return rc;
}

int eth_tx_encode_signed(const eth_tx_t *tx, int recid, const uint8_t r[32], const uint8_t s[32], uint8_t *out,
                         size_t cap, size_t *out_len)
{
    if (recid != 0 && recid != 1) return -1;
    return encode(tx, recid, r, s, out, cap, out_len);
}
