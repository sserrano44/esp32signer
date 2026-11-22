#include "cJSON.h"
#include "eth_tx.h"
#include "hex.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define MAX_CHAIN_ID ((uint64_t)1 << 53)

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* 1 = present & parsed, 0 = absent/null, -1 = invalid */
static int get_qty(const cJSON *obj, const char *name, uint8_t out[32])
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    memset(out, 0, 32);
    if (!it || cJSON_IsNull(it)) return 0;
    if (cJSON_IsString(it)) return u256_from_hex(it->valuestring, out) == 0 ? 1 : -1;
    if (cJSON_IsNumber(it)) {
        double d = it->valuedouble;
        if (d < 0 || d > 9007199254740991.0 || d != (double)(uint64_t)d) return -1;
        u256_from_u64((uint64_t)d, out);
        return 1;
    }
    return -1;
}

static int get_u64(const cJSON *obj, const char *name, uint64_t *out)
{
    uint8_t tmp[32];
    int rc = get_qty(obj, name, tmp);
    if (rc != 1) return rc;
    return u256_to_u64(tmp, out) == 0 ? 1 : -1;
}

static int get_data(const cJSON *obj, const char *name, eth_tx_t *tx, int *present)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, name);
    *present = 0;
    if (!it || cJSON_IsNull(it)) return 0;
    if (!cJSON_IsString(it)) return -1;
    const char *s = it->valuestring;
    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    int n = hex_decode(s, tx->data, ETH_TX_MAX_DATA);
    if (n < 0) return -1;
    tx->data_len = (size_t)n;
    *present = 1;
    return 0;
}

static int parse_access_list(const cJSON *al, eth_tx_t *tx, char *err, size_t errlen)
{
    if (!cJSON_IsArray(al)) return fail(err, errlen, "accessList must be an array");
    const cJSON *entry;
    cJSON_ArrayForEach(entry, al)
    {
        if (tx->al_count >= ETH_TX_MAX_AL_ADDRS) return fail(err, errlen, "accessList too long");
        eth_al_entry_t *e = &tx->al[tx->al_count];
        const cJSON *addr = cJSON_GetObjectItemCaseSensitive(entry, "address");
        const cJSON *keys = cJSON_GetObjectItemCaseSensitive(entry, "storageKeys");
        if (!cJSON_IsString(addr) || addr_from_hex(addr->valuestring, e->addr) != 0)
            return fail(err, errlen, "accessList: bad address");
        e->key_start = (uint16_t)tx->al_keys_count;
        e->key_count = 0;
        if (keys && !cJSON_IsNull(keys)) {
            if (!cJSON_IsArray(keys)) return fail(err, errlen, "accessList: storageKeys must be an array");
            const cJSON *k;
            cJSON_ArrayForEach(k, keys)
            {
                if (tx->al_keys_count >= ETH_TX_MAX_AL_KEYS) return fail(err, errlen, "accessList: too many keys");
                if (!cJSON_IsString(k) || hex_decode(k->valuestring, tx->al_keys[tx->al_keys_count], 32) != 32)
                    return fail(err, errlen, "accessList: bad storage key");
                tx->al_keys_count++;
                e->key_count++;
            }
        }
        tx->al_count++;
    }
    return 0;
}

int eth_tx_from_json(const cJSON *obj, eth_tx_t *tx, char *err, size_t errlen)
{
    memset(tx, 0, sizeof(*tx));
    if (!cJSON_IsObject(obj)) return fail(err, errlen, "transaction must be an object");

    static const char *forbidden[] = {"authorizationList", "blobVersionedHashes", "maxFeePerBlobGas", "blobs"};
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
        if (cJSON_GetObjectItemCaseSensitive(obj, forbidden[i]))
            return fail(err, errlen, "field '%s' is not supported", forbidden[i]);

    uint8_t tmp[32];
    int has_1559 = get_qty(obj, "maxFeePerGas", tx->max_fee);
    int has_prio = get_qty(obj, "maxPriorityFeePerGas", tx->max_prio);
    int has_gp = get_qty(obj, "gasPrice", tx->gas_price);
    if (has_1559 < 0 || has_prio < 0 || has_gp < 0) return fail(err, errlen, "invalid fee field");

    int trc = get_qty(obj, "type", tmp);
    if (trc < 0) return fail(err, errlen, "invalid type");
    if (trc == 1) {
        uint64_t t;
        if (u256_to_u64(tmp, &t) != 0 || (t != 0 && t != 2))
            return fail(err, errlen, "unsupported transaction type (only 0x0 and 0x2 are allowed)");
        tx->type = (uint8_t)t;
    } else if (has_1559 == 1 || has_prio == 1) {
        tx->type = ETH_TX_TYPE_EIP1559;
    } else if (has_gp == 1) {
        tx->type = ETH_TX_TYPE_LEGACY;
    } else {
        return fail(err, errlen, "missing fee fields (maxFeePerGas/maxPriorityFeePerGas or gasPrice)");
    }

    if (tx->type == ETH_TX_TYPE_EIP1559) {
        if (has_1559 != 1 || has_prio != 1)
            return fail(err, errlen, "type 0x2 requires maxFeePerGas and maxPriorityFeePerGas");
        if (has_gp == 1) return fail(err, errlen, "gasPrice not allowed with type 0x2");
        if (u256_cmp(tx->max_prio, tx->max_fee) > 0)
            return fail(err, errlen, "maxPriorityFeePerGas exceeds maxFeePerGas");
    } else {
        if (has_gp != 1) return fail(err, errlen, "type 0x0 requires gasPrice");
        if (has_1559 == 1 || has_prio == 1) return fail(err, errlen, "EIP-1559 fee fields not allowed with type 0x0");
    }

    int rc = get_u64(obj, "chainId", &tx->chain_id);
    if (rc != 1 || tx->chain_id == 0 || tx->chain_id > MAX_CHAIN_ID)
        return fail(err, errlen, "chainId is required (device has no node access)");
    if (get_u64(obj, "nonce", &tx->nonce) != 1) return fail(err, errlen, "nonce is required (device has no node access)");
    rc = get_u64(obj, "gas", &tx->gas);
    if (rc == 0) rc = get_u64(obj, "gasLimit", &tx->gas);
    if (rc != 1) return fail(err, errlen, "gas is required (device has no node access)");

    if (get_qty(obj, "value", tx->value) < 0) return fail(err, errlen, "invalid value");

    const cJSON *to = cJSON_GetObjectItemCaseSensitive(obj, "to");
    if (to && !cJSON_IsNull(to)) {
        if (!cJSON_IsString(to) || addr_from_hex(to->valuestring, tx->to) != 0)
            return fail(err, errlen, "invalid 'to' address");
        tx->has_to = 1;
    }
    const cJSON *from = cJSON_GetObjectItemCaseSensitive(obj, "from");
    if (from && !cJSON_IsNull(from)) {
        if (!cJSON_IsString(from) || addr_from_hex(from->valuestring, tx->from) != 0)
            return fail(err, errlen, "invalid 'from' address");
        tx->has_from = 1;
    }

    /* data / input: accept either; if both present they must match. */
    int has_data = 0, has_input = 0;
    if (get_data(obj, "input", tx, &has_input) < 0) return fail(err, errlen, "invalid or too large 'input'");
    if (has_input) {
        const cJSON *d = cJSON_GetObjectItemCaseSensitive(obj, "data");
        if (d && !cJSON_IsNull(d)) {
            const cJSON *in = cJSON_GetObjectItemCaseSensitive(obj, "input");
            if (!cJSON_IsString(d) || strcasecmp(d->valuestring, in->valuestring) != 0)
                return fail(err, errlen, "'data' and 'input' differ");
        }
    } else if (get_data(obj, "data", tx, &has_data) < 0) {
        return fail(err, errlen, "invalid or too large 'data'");
    }

    const cJSON *al = cJSON_GetObjectItemCaseSensitive(obj, "accessList");
    if (al && !cJSON_IsNull(al)) {
        if (parse_access_list(al, tx, err, errlen) != 0) return -1;
        if (tx->type == ETH_TX_TYPE_LEGACY && tx->al_count)
            return fail(err, errlen, "accessList not allowed with type 0x0");
    }
    return 0;
}
