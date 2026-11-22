#include "policy.h"
#include "cJSON.h"
#include "hex.h"
#include "regex.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bit i set = entry applies on policy->chain_ids[i]. */
typedef uint32_t chain_mask_t;
#define CHAIN_MASK_ALL ((chain_mask_t)0xFFFFFFFFu)

typedef struct {
    uint8_t to[20];
    uint8_t max_value[32];
    char label[48];
    chain_mask_t chains;
} native_rule_t;

typedef struct {
    uint64_t max_gas;
    uint8_t max_fee[32];
    uint8_t max_prio[32];
} limits_t;

typedef struct {
    char name[48];
    regex_prog_t *re;
} calldata_rule_t;

typedef struct {
    uint8_t addr[20];
    uint8_t max_value[32];
    char label[48];
    chain_mask_t chains;
    size_t n_rules;
    calldata_rule_t *rules;
} contract_t;

struct policy {
    size_t n_chain;
    uint64_t chain_ids[POLICY_MAX_CHAIN_IDS];
    limits_t limits[POLICY_MAX_CHAIN_IDS]; /* per chain index; global limits unless overridden */
    uint32_t rate_per_minute; /* 0 = unlimited */
    uint64_t bucket;          /* tokens * 60000 */
    uint64_t bucket_ms;
    int bucket_init;
    size_t n_native;
    native_rule_t *natives;
    size_t n_contracts;
    contract_t *contracts;
    size_t total_insts;
};

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

static int check_keys(const cJSON *obj, const char *const *allowed, const char *where, char *err, size_t errlen)
{
    if (!cJSON_IsObject(obj)) return fail(err, errlen, "%s must be an object", where);
    const cJSON *it;
    cJSON_ArrayForEach(it, obj)
    {
        int ok = 0;
        for (const char *const *a = allowed; *a; a++)
            if (!strcmp(it->string, *a)) ok = 1;
        if (!ok) return fail(err, errlen, "%s: unknown key '%s'", where, it->string);
    }
    return 0;
}

static int get_wei(const cJSON *obj, const char *key, uint8_t out[32], int required, const char *where, char *err,
                   size_t errlen)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!it) {
        memset(out, 0, 32);
        return required ? fail(err, errlen, "%s: missing '%s'", where, key) : 0;
    }
    if (!cJSON_IsString(it) || u256_from_dec(it->valuestring, out) != 0)
        return fail(err, errlen, "%s: '%s' must be a decimal wei string", where, key);
    return 0;
}

static int get_uint(const cJSON *obj, const char *key, uint64_t *out, int required, const char *where, char *err,
                    size_t errlen)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!it) {
        *out = 0;
        return required ? fail(err, errlen, "%s: missing '%s'", where, key) : 0;
    }
    if (!cJSON_IsNumber(it) || it->valuedouble < 0 || it->valuedouble > 9007199254740991.0 ||
        it->valuedouble != (double)(uint64_t)it->valuedouble)
        return fail(err, errlen, "%s: '%s' must be a non-negative integer", where, key);
    *out = (uint64_t)it->valuedouble;
    return 0;
}

static void copy_label(char *dst, size_t cap, const cJSON *obj, const char *key)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    dst[0] = 0;
    if (cJSON_IsString(it)) snprintf(dst, cap, "%s", it->valuestring);
}

/* Replace all occurrences of `pat` in `s`; returns newly malloc'ed string. */
static char *replace_all(const char *s, const char *pat, const char *rep)
{
    size_t pl = strlen(pat), rl = strlen(rep), count = 0;
    for (const char *p = strstr(s, pat); p; p = strstr(p + pl, pat)) count++;
    char *out = malloc(strlen(s) + count * (rl > pl ? rl - pl : 0) + 1);
    if (!out) return NULL;
    char *o = out;
    while (*s) {
        if (!strncmp(s, pat, pl)) {
            memcpy(o, rep, rl);
            o += rl;
            s += pl;
        } else {
            *o++ = *s++;
        }
    }
    *o = 0;
    return out;
}

static int parse_addr_field(const cJSON *obj, const char *key, const uint8_t *self, uint8_t out[20], const char *where,
                            char *err, size_t errlen)
{
    const cJSON *it = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(it)) return fail(err, errlen, "%s: '%s' must be an address string", where, key);
    if (!strcmp(it->valuestring, "{{self}}")) {
        if (!self) return fail(err, errlen, "%s: uses {{self}} but no signer key is provisioned yet", where);
        memcpy(out, self, 20);
        return 0;
    }
    if (addr_from_hex(it->valuestring, out) != 0) return fail(err, errlen, "%s: invalid address '%s'", where, it->valuestring);
    return 0;
}

static int is_anchored(const char *re)
{
    size_t n = strlen(re);
    if (n < 2 || re[0] != '^' || re[n - 1] != '$') return 0;
    /* '$' must not be escaped: count preceding backslashes */
    size_t bs = 0;
    for (size_t i = n - 1; i > 0 && re[i - 1] == '\\'; i--) bs++;
    return (bs % 2) == 0;
}

static int compile_rule(policy_t *p, const cJSON *jr, const uint8_t *self, calldata_rule_t *out, const char *where,
                        char *err, size_t errlen)
{
    static const char *const keys[] = {"name", "calldata", NULL};
    if (check_keys(jr, keys, where, err, errlen)) return -1;
    copy_label(out->name, sizeof(out->name), jr, "name");
    const cJSON *cd = cJSON_GetObjectItemCaseSensitive(jr, "calldata");
    if (!cJSON_IsString(cd)) return fail(err, errlen, "%s: 'calldata' regex string required", where);

    char selfhex[41], selfword[65];
    char *expanded;
    if (self) {
        hex_encode(self, 20, selfhex);
        memset(selfword, '0', 24);
        memcpy(selfword + 24, selfhex, 41);
        char *tmp = replace_all(cd->valuestring, "{{addr:self}}", selfword);
        expanded = tmp ? replace_all(tmp, "{{self}}", selfhex) : NULL;
        free(tmp);
    } else {
        expanded = strdup(cd->valuestring);
    }
    if (!expanded) return fail(err, errlen, "out of memory");
    if (strstr(expanded, "{{")) {
        free(expanded);
        return fail(err, errlen, "%s: unexpanded macro in calldata regex%s", where,
                    self ? "" : " (is a signer key provisioned?)");
    }
    if (!is_anchored(expanded)) {
        free(expanded);
        return fail(err, errlen, "%s: calldata regex must start with ^ and end with $", where);
    }
    char rerr[96];
    int rc = regex_compile(expanded, &out->re, rerr, sizeof(rerr));
    free(expanded);
    if (rc != 0) return fail(err, errlen, "%s: regex error: %s", where, rerr);
    p->total_insts += regex_prog_insts(out->re);
    if (p->total_insts > POLICY_MAX_TOTAL_INSTS)
        return fail(err, errlen, "policy regexes too large (%u instructions, max %u)", (unsigned)p->total_insts,
                    (unsigned)POLICY_MAX_TOTAL_INSTS);
    return 0;
}

static int chain_index(const policy_t *p, uint64_t chain_id)
{
    for (size_t i = 0; i < p->n_chain; i++)
        if (p->chain_ids[i] == chain_id) return (int)i;
    return -1;
}

static int parse_chain_id(const cJSON *c, uint64_t *out)
{
    if (!cJSON_IsNumber(c) || c->valuedouble < 1 || c->valuedouble > 9007199254740991.0 ||
        c->valuedouble != (double)(uint64_t)c->valuedouble)
        return -1;
    *out = (uint64_t)c->valuedouble;
    return 0;
}

/* Optional "chain_ids" on an entry: restricts it to a subset of the policy's chains. */
static int parse_chain_mask(const policy_t *p, const cJSON *obj, chain_mask_t *out, const char *where, char *err,
                            size_t errlen)
{
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(obj, "chain_ids");
    if (!arr) {
        *out = CHAIN_MASK_ALL;
        return 0;
    }
    if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) == 0)
        return fail(err, errlen, "%s: 'chain_ids' must be a non-empty array", where);
    *out = 0;
    const cJSON *c;
    cJSON_ArrayForEach(c, arr)
    {
        uint64_t id;
        if (parse_chain_id(c, &id)) return fail(err, errlen, "%s: chain_ids must be positive integers", where);
        int idx = chain_index(p, id);
        if (idx < 0) return fail(err, errlen, "%s: chain %llu is not in the policy's chain_ids", where, (unsigned long long)id);
        if (*out & (1u << idx)) return fail(err, errlen, "%s: duplicate chain %llu", where, (unsigned long long)id);
        *out |= 1u << idx;
    }
    return 0;
}

static int parse_limits(const cJSON *obj, limits_t *l, const char *where, char *err, size_t errlen)
{
    if (get_uint(obj, "max_gas", &l->max_gas, 1, where, err, errlen)) return -1;
    if (get_wei(obj, "max_fee_per_gas", l->max_fee, 1, where, err, errlen)) return -1;
    if (get_wei(obj, "max_priority_fee_per_gas", l->max_prio, 1, where, err, errlen)) return -1;
    return 0;
}

static int load(policy_t *p, const cJSON *root, const uint8_t *self, char *err, size_t errlen)
{
    static const char *const top_keys[] = {"version", "chain_ids", "limits", "chain_limits", "native_transfers", "contracts", "name", NULL};
    static const char *const limit_keys[] = {"max_gas", "max_fee_per_gas", "max_priority_fee_per_gas", "rate_per_minute", NULL};
    static const char *const chain_limit_keys[] = {"chain_id", "max_gas", "max_fee_per_gas", "max_priority_fee_per_gas", NULL};
    static const char *const native_keys[] = {"to", "max_value", "label", "chain_ids", NULL};
    static const char *const contract_keys[] = {"address", "max_value", "label", "rules", "chain_ids", NULL};

    if (check_keys(root, top_keys, "policy", err, errlen)) return -1;
    uint64_t version;
    if (get_uint(root, "version", &version, 1, "policy", err, errlen)) return -1;
    if (version != 1) return fail(err, errlen, "unsupported policy version %llu", (unsigned long long)version);

    const cJSON *chains = cJSON_GetObjectItemCaseSensitive(root, "chain_ids");
    if (!cJSON_IsArray(chains) || cJSON_GetArraySize(chains) == 0)
        return fail(err, errlen, "chain_ids must be a non-empty array");
    if (cJSON_GetArraySize(chains) > POLICY_MAX_CHAIN_IDS) return fail(err, errlen, "too many chain_ids");
    const cJSON *c;
    cJSON_ArrayForEach(c, chains)
    {
        uint64_t id;
        if (parse_chain_id(c, &id)) return fail(err, errlen, "chain_ids must be positive integers");
        if (chain_index(p, id) >= 0) return fail(err, errlen, "chain_ids: duplicate chain %llu", (unsigned long long)id);
        p->chain_ids[p->n_chain++] = id;
    }

    const cJSON *limits = cJSON_GetObjectItemCaseSensitive(root, "limits");
    if (!limits) return fail(err, errlen, "policy: missing 'limits'");
    if (check_keys(limits, limit_keys, "limits", err, errlen)) return -1;
    uint64_t rate;
    limits_t global;
    if (parse_limits(limits, &global, "limits", err, errlen)) return -1;
    if (get_uint(limits, "rate_per_minute", &rate, 0, "limits", err, errlen)) return -1;
    if (rate > 100000) return fail(err, errlen, "limits: rate_per_minute too large");
    p->rate_per_minute = (uint32_t)rate;
    for (size_t i = 0; i < p->n_chain; i++) p->limits[i] = global;

    /* Optional per-chain overrides (all three caps required in each entry). */
    const cJSON *cls = cJSON_GetObjectItemCaseSensitive(root, "chain_limits");
    if (cls) {
        if (!cJSON_IsArray(cls)) return fail(err, errlen, "chain_limits must be an array");
        chain_mask_t seen = 0;
        unsigned k = 0;
        const cJSON *jl;
        cJSON_ArrayForEach(jl, cls)
        {
            char where[40];
            snprintf(where, sizeof(where), "chain_limits[%u]", k++);
            if (check_keys(jl, chain_limit_keys, where, err, errlen)) return -1;
            uint64_t id;
            if (parse_chain_id(cJSON_GetObjectItemCaseSensitive(jl, "chain_id"), &id))
                return fail(err, errlen, "%s: 'chain_id' must be a positive integer", where);
            int idx = chain_index(p, id);
            if (idx < 0) return fail(err, errlen, "%s: chain %llu is not in chain_ids", where, (unsigned long long)id);
            if (seen & (1u << idx)) return fail(err, errlen, "%s: duplicate chain %llu", where, (unsigned long long)id);
            seen |= 1u << idx;
            if (parse_limits(jl, &p->limits[idx], where, err, errlen)) return -1;
        }
    }

    const cJSON *natives = cJSON_GetObjectItemCaseSensitive(root, "native_transfers");
    if (natives) {
        if (!cJSON_IsArray(natives)) return fail(err, errlen, "native_transfers must be an array");
        int n = cJSON_GetArraySize(natives);
        if (n > POLICY_MAX_NATIVE) return fail(err, errlen, "too many native_transfers");
        p->natives = calloc((size_t)n + 1, sizeof(native_rule_t));
        if (!p->natives) return fail(err, errlen, "out of memory");
        const cJSON *jn;
        cJSON_ArrayForEach(jn, natives)
        {
            char where[48];
            snprintf(where, sizeof(where), "native_transfers[%u]", (unsigned)p->n_native);
            native_rule_t *nr = &p->natives[p->n_native];
            if (check_keys(jn, native_keys, where, err, errlen)) return -1;
            if (parse_addr_field(jn, "to", self, nr->to, where, err, errlen)) return -1;
            if (get_wei(jn, "max_value", nr->max_value, 1, where, err, errlen)) return -1;
            copy_label(nr->label, sizeof(nr->label), jn, "label");
            if (parse_chain_mask(p, jn, &nr->chains, where, err, errlen)) return -1;
            for (size_t i = 0; i < p->n_native; i++)
                if (!memcmp(p->natives[i].to, nr->to, 20) && (p->natives[i].chains & nr->chains))
                    return fail(err, errlen, "%s: duplicate address on the same chain", where);
            p->n_native++;
        }
    }

    const cJSON *contracts = cJSON_GetObjectItemCaseSensitive(root, "contracts");
    if (contracts) {
        if (!cJSON_IsArray(contracts)) return fail(err, errlen, "contracts must be an array");
        int n = cJSON_GetArraySize(contracts);
        if (n > POLICY_MAX_CONTRACTS) return fail(err, errlen, "too many contracts");
        p->contracts = calloc((size_t)n + 1, sizeof(contract_t));
        if (!p->contracts) return fail(err, errlen, "out of memory");
        const cJSON *jc;
        cJSON_ArrayForEach(jc, contracts)
        {
            char where[64];
            snprintf(where, sizeof(where), "contracts[%u]", (unsigned)p->n_contracts);
            contract_t *ct = &p->contracts[p->n_contracts];
            if (check_keys(jc, contract_keys, where, err, errlen)) return -1;
            if (parse_addr_field(jc, "address", self, ct->addr, where, err, errlen)) return -1;
            if (get_wei(jc, "max_value", ct->max_value, 1, where, err, errlen)) return -1;
            copy_label(ct->label, sizeof(ct->label), jc, "label");
            if (parse_chain_mask(p, jc, &ct->chains, where, err, errlen)) return -1;
            for (size_t i = 0; i < p->n_contracts; i++)
                if (!memcmp(p->contracts[i].addr, ct->addr, 20) && (p->contracts[i].chains & ct->chains))
                    return fail(err, errlen, "%s: duplicate address on the same chain", where);
            p->n_contracts++; /* counted now so policy_free releases partial rules */

            const cJSON *rules = cJSON_GetObjectItemCaseSensitive(jc, "rules");
            if (!cJSON_IsArray(rules) || cJSON_GetArraySize(rules) == 0)
                return fail(err, errlen, "%s: 'rules' must be a non-empty array", where);
            int nr = cJSON_GetArraySize(rules);
            if (nr > POLICY_MAX_RULES_PER_CONTRACT) return fail(err, errlen, "%s: too many rules", where);
            ct->rules = calloc((size_t)nr, sizeof(calldata_rule_t));
            if (!ct->rules) return fail(err, errlen, "out of memory");
            const cJSON *jr;
            cJSON_ArrayForEach(jr, rules)
            {
                char rwhere[96];
                snprintf(rwhere, sizeof(rwhere), "%s.rules[%u]", where, (unsigned)ct->n_rules);
                if (compile_rule(p, jr, self, &ct->rules[ct->n_rules], rwhere, err, errlen)) {
                    ct->n_rules++; /* free partially compiled entry */
                    return -1;
                }
                ct->n_rules++;
            }
        }
    }
    if (p->n_native == 0 && p->n_contracts == 0)
        return fail(err, errlen, "policy allows nothing (no native_transfers or contracts)");
    return 0;
}

int policy_load(const char *json, size_t len, const uint8_t *self_addr, policy_t **out, char *err, size_t errlen)
{
    *out = NULL;
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) return fail(err, errlen, "policy is not valid JSON");
    policy_t *p = calloc(1, sizeof(*p));
    if (!p) {
        cJSON_Delete(root);
        return fail(err, errlen, "out of memory");
    }
    int rc = load(p, root, self_addr, err, errlen);
    cJSON_Delete(root);
    if (rc) {
        policy_free(p);
        return -1;
    }
    *out = p;
    return 0;
}

void policy_free(policy_t *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->n_contracts; i++) {
        for (size_t r = 0; r < p->contracts[i].n_rules; r++) regex_free(p->contracts[i].rules[r].re);
        free(p->contracts[i].rules);
    }
    free(p->contracts);
    free(p->natives);
    free(p);
}

size_t policy_total_insts(const policy_t *p)
{
    return p->total_insts;
}

static int deny(policy_result_t *res, const char *fmt, ...)
{
    va_list ap;
    res->allowed = 0;
    va_start(ap, fmt);
    vsnprintf(res->reason, sizeof(res->reason), fmt, ap);
    va_end(ap);
    return 0;
}

static int rate_take(policy_t *p, uint64_t now_ms)
{
    if (!p->rate_per_minute) return 1;
    const uint64_t one = 60000, cap = (uint64_t)p->rate_per_minute * one;
    if (!p->bucket_init) {
        p->bucket = cap;
        p->bucket_ms = now_ms;
        p->bucket_init = 1;
    }
    if (now_ms > p->bucket_ms) {
        uint64_t add = (now_ms - p->bucket_ms) * p->rate_per_minute;
        p->bucket = (cap - p->bucket < add) ? cap : p->bucket + add;
        p->bucket_ms = now_ms;
    }
    if (p->bucket < one) return 0;
    p->bucket -= one;
    return 1;
}

static int check(policy_t *p, const eth_tx_t *tx, uint64_t now_ms, policy_result_t *res)
{
    char tohex[43], a[80], b[80];
    memset(res, 0, sizeof(*res));

    if (tx->type != ETH_TX_TYPE_LEGACY && tx->type != ETH_TX_TYPE_EIP1559)
        return deny(res, "transaction type 0x%x not allowed", tx->type);

    int ci = chain_index(p, tx->chain_id);
    if (ci < 0) return deny(res, "chainId %llu not allowed", (unsigned long long)tx->chain_id);
    const limits_t *lim = &p->limits[ci];
    const chain_mask_t bit = 1u << ci;

    if (tx->gas > lim->max_gas)
        return deny(res, "gas %llu exceeds max_gas %llu", (unsigned long long)tx->gas, (unsigned long long)lim->max_gas);
    const uint8_t *fee = tx->type == ETH_TX_TYPE_EIP1559 ? tx->max_fee : tx->gas_price;
    if (u256_cmp(fee, lim->max_fee) > 0) {
        u256_to_dec(fee, a);
        u256_to_dec(lim->max_fee, b);
        return deny(res, "fee per gas %s exceeds cap %s", a, b);
    }
    if (tx->type == ETH_TX_TYPE_EIP1559 && u256_cmp(tx->max_prio, lim->max_prio) > 0) {
        u256_to_dec(tx->max_prio, a);
        u256_to_dec(lim->max_prio, b);
        return deny(res, "priority fee %s exceeds cap %s", a, b);
    }

    if (!tx->has_to) return deny(res, "contract creation not allowed");
    addr_to_hex(tx->to, tohex);

    if (tx->data_len == 0) {
        for (size_t i = 0; i < p->n_native; i++) {
            const native_rule_t *nr = &p->natives[i];
            if (!(nr->chains & bit) || memcmp(nr->to, tx->to, 20)) continue;
            if (u256_cmp(tx->value, nr->max_value) > 0) {
                u256_to_dec(tx->value, a);
                return deny(res, "value %s exceeds max_value for native transfer to %s", a, tohex);
            }
            if (!rate_take(p, now_ms)) return deny(res, "rate limit exceeded");
            res->allowed = 1;
            snprintf(res->reason, sizeof(res->reason), "native_transfer:%s", nr->label[0] ? nr->label : tohex);
            return 1;
        }
    }

    for (size_t i = 0; i < p->n_contracts; i++) {
        contract_t *ct = &p->contracts[i];
        if (!(ct->chains & bit) || memcmp(ct->addr, tx->to, 20)) continue;
        const char *label = ct->label[0] ? ct->label : tohex;
        if (u256_cmp(tx->value, ct->max_value) > 0) {
            u256_to_dec(tx->value, a);
            return deny(res, "value %s exceeds max_value for contract %s", a, label);
        }
        char *hexdata = malloc(tx->data_len * 2 + 1);
        if (!hexdata) return deny(res, "out of memory");
        hex_encode(tx->data, tx->data_len, hexdata);
        int budget_hit = 0;
        for (size_t r = 0; r < ct->n_rules; r++) {
            int m = regex_full_match(ct->rules[r].re, hexdata, tx->data_len * 2);
            if (m == 1) {
                free(hexdata);
                if (!rate_take(p, now_ms)) return deny(res, "rate limit exceeded");
                res->allowed = 1;
                snprintf(res->reason, sizeof(res->reason), "%s:%s", label,
                         ct->rules[r].name[0] ? ct->rules[r].name : "rule");
                return 1;
            }
            if (m < 0) budget_hit = 1;
        }
        char sel[9] = "none";
        if (tx->data_len >= 4) hex_encode(tx->data, 4, sel);
        free(hexdata);
        return deny(res, "calldata (selector 0x%s) matched no rule for contract %s%s", sel, label,
                    budget_hit ? " (regex step budget exceeded)" : "");
    }

    if (tx->data_len == 0) return deny(res, "native transfer to %s not whitelisted", tohex);
    return deny(res, "destination %s not whitelisted", tohex);
}

void policy_check(policy_t *p, const eth_tx_t *tx, uint64_t now_ms, policy_result_t *res)
{
    (void)check(p, tx, now_ms, res);
}
