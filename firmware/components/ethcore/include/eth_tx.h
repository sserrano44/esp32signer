#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_TX_MAX_DATA 16384
#define ETH_TX_MAX_AL_ADDRS 32
#define ETH_TX_MAX_AL_KEYS 128
/* data + access list + fixed fields + signature, with margin */
#define ETH_TX_MAX_ENCODED (ETH_TX_MAX_DATA + ETH_TX_MAX_AL_ADDRS * 32 + ETH_TX_MAX_AL_KEYS * 34 + 512)

#define ETH_TX_TYPE_LEGACY 0
#define ETH_TX_TYPE_EIP1559 2

typedef struct {
    uint8_t addr[20];
    uint16_t key_start;
    uint16_t key_count;
} eth_al_entry_t;

/* Large (~22 KB): allocate on the heap. */
typedef struct {
    uint8_t type;
    uint64_t chain_id;
    uint64_t nonce;
    uint64_t gas;
    uint8_t gas_price[32]; /* legacy only */
    uint8_t max_fee[32];   /* EIP-1559 maxFeePerGas */
    uint8_t max_prio[32];  /* EIP-1559 maxPriorityFeePerGas */
    int has_to;
    uint8_t to[20];
    uint8_t value[32];
    int has_from;
    uint8_t from[20];
    size_t data_len;
    uint8_t data[ETH_TX_MAX_DATA];
    size_t al_count;
    eth_al_entry_t al[ETH_TX_MAX_AL_ADDRS];
    size_t al_keys_count;
    uint8_t al_keys[ETH_TX_MAX_AL_KEYS][32];
} eth_tx_t;

/* Unsigned payload that is hashed for signing (EIP-155 / EIP-2718). */
int eth_tx_signing_payload(const eth_tx_t *tx, uint8_t *out, size_t cap, size_t *out_len);
int eth_tx_signing_hash(const eth_tx_t *tx, uint8_t hash[32]);
/* Final raw transaction. recid in {0,1}. */
int eth_tx_encode_signed(const eth_tx_t *tx, int recid, const uint8_t r[32], const uint8_t s[32],
                         uint8_t *out, size_t cap, size_t *out_len);

/* Parse a JSON-RPC transaction object (cJSON*). Returns 0 or -1 with `err` set. */
struct cJSON;
int eth_tx_from_json(const struct cJSON *obj, eth_tx_t *tx, char *err, size_t errlen);

/* Name of the first object member that repeats a sibling's name, at any
 * depth, or NULL. cJSON keeps duplicates and lookups return the first, while
 * many other parsers keep the last: strict inputs reject them. */
const char *json_duplicate_key(const struct cJSON *item);

#ifdef __cplusplus
}
#endif
