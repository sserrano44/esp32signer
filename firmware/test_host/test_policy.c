#include "eth_tx.h"
#include "hex.h"
#include "policy.h"
#include "regex.h"
#include "test_util.h"
#include <time.h>

/* ------------------------------------------------------------- regex --- */

static void re_case(const char *pat, const char *in, int want)
{
    regex_prog_t *p;
    char err[96];
    int rc = regex_compile(pat, &p, err, sizeof(err));
    CHECK(rc == 0, "compile '%s': %s", pat, err);
    if (rc) return;
    int got = regex_full_match(p, in, strlen(in));
    CHECK(got == want, "'%s' on '%s': got %d want %d", pat, in, got, want);
    regex_free(p);
}

static void re_bad(const char *pat)
{
    regex_prog_t *p = NULL;
    char err[96];
    CHECK(regex_compile(pat, &p, err, sizeof(err)) != 0, "expected compile error for '%s'", pat);
    regex_free(p);
}

static void test_regex(void)
{
    re_case("^abc$", "abc", 1);
    re_case("^abc$", "abcd", 0);
    re_case("abc", "xabc", 0); /* always full match */
    re_case("abc", "abc", 1);
    re_case("^a|b$", "b", 1);
    re_case("^a|b$", "ab", 0);
    re_case("^(a|b)*$", "abab", 1);
    re_case("^(a|b)*$", "", 1);
    re_case("^a{3}$", "aaa", 1);
    re_case("^a{3}$", "aa", 0);
    re_case("^a{2,3}$", "aaaa", 0);
    re_case("^a{2,3}$", "aa", 1);
    re_case("^a{2,}$", "aaaaa", 1);
    re_case("^a{0,2}b$", "b", 1);
    re_case("^[0-9a-f]{4}$", "00ff", 1);
    re_case("^[0-9a-f]{4}$", "00fF", 0);
    re_case("^[^x]+$", "abc", 1);
    re_case("^[^x]+$", "axc", 0);
    re_case("^\\.$", ".", 1);
    re_case("^\\.$", "x", 0);
    re_case("^.$", "x", 1);
    re_case("^(?:ab)+$", "abab", 1);
    re_case("^(?:ab)+$", "aba", 0);
    re_case("^$", "", 1);
    re_case("^$", "a", 0);
    re_case("^a?b$", "b", 1);
    re_case("^((a|b){2}c)+$", "abcbac", 1);
    re_case("^((a|b){2}c)+$", "abcbc", 0);
    re_case("^\\d+$", "0123", 1);
    /* Literal runs are one node: a quantifier binds to the last character only. */
    re_case("^abb{2}c$", "abbbc", 1);
    re_case("^abb{2}c$", "abbc", 0);
    re_case("^ab*c$", "ac", 1);
    re_case("^xab+$", "xabbb", 1);
    re_case("^xab+$", "xab", 1);
    re_case("^xab?$", "xa", 1);
    re_case("^ab-c/d$", "ab-c/d", 1);
    re_case("^ab\\.cd$", "ab.cd", 1);
    re_case("^ab\\.cd$", "abxcd", 0);
    re_case("^(?:abc|de)fg$", "defg", 1);
    re_case("^(?:abc|de)fg$", "abfg", 0);
    re_case("^ab(cd)?ef$", "abef", 1);
    re_case("^ab(cd)?ef$", "abcdef", 1);
    re_case("^00[0-9a-f]{2}11$", "00ab11", 1);
    re_bad("^ab]$");
    re_bad("^ab}$");
    re_case("^[]a]$", "]", 1);
    re_case("^(abc|abd|x)(1|2|3|4)$", "abd3", 1);
    re_case("^(abc|abd|x)(1|2|3|4)$", "abe3", 0);

    re_bad("^(ab$");
    re_bad("^ab)$");
    re_bad("^a{2,1}$");
    re_bad("^*a$");
    re_bad("^[a-$");
    re_bad("^a{5000}$");
    re_bad("^\\1$");
    re_bad("^a*?$");
    re_bad("^(?=a)$");
    re_bad("^[0-9a-f]{64}{64}{64}$"); /* too many instructions */

    /* Pathological for backtracking engines: must be linear and fast. */
    {
        size_t n = 20000;
        char *s = malloc(n + 1);
        memset(s, 'a', n);
        s[n] = 0;
        regex_prog_t *p;
        char err[96];
        CHECK(regex_compile("^(a|a)*(a*)*b$", &p, err, sizeof(err)) == 0, "%s", err);
        clock_t t0 = clock();
        int r = regex_full_match(p, s, n);
        double ms = (double)(clock() - t0) * 1000.0 / CLOCKS_PER_SEC;
        CHECK(r == 0, "pathological result %d", r);
        CHECK(ms < 500, "pathological took %.1f ms", ms);
        regex_free(p);
        free(s);
    }
    /* Very long literal pattern must not blow the stack. */
    {
        size_t n = 7000;
        char *pat = malloc(n + 3), *s = malloc(n + 1);
        pat[0] = '^';
        for (size_t i = 0; i < n; i++) s[i] = pat[1 + i] = "0123456789abcdef"[i % 16];
        pat[n + 1] = '$';
        pat[n + 2] = 0;
        s[n] = 0;
        regex_prog_t *p;
        char err[96];
        CHECK(regex_compile(pat, &p, err, sizeof(err)) == 0, "long literal: %s", err);
        if (p) {
            CHECK(regex_full_match(p, s, n) == 1, "long literal match");
            s[n - 1] = 'x';
            CHECK(regex_full_match(p, s, n) == 0, "long literal mismatch");
            regex_free(p);
        }
        free(pat);
        free(s);
    }
}

/* ------------------------------------------------------------ policy --- */

#define SELF "0x1234567890abcdef1234567890abcdef12345678"
#define USDC "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
#define PERMIT2 "0x000000000022d473030f116ddee9f6b43ac78ba3"
#define ROUTER "0x6ff5693b99212da76ad316178a184ab56d299b43"
#define TREASURY "0x9999999999999999999999999999999999999999"
#define EVIL "0xbadbadbadbadbadbadbadbadbadbadbadbadbad0"

static const char *POLICY_JSON =
    "{\"version\":1,\"name\":\"test\",\"chain_ids\":[8453],"
    "\"limits\":{\"max_gas\":3000000,\"max_fee_per_gas\":\"5000000000\",\"max_priority_fee_per_gas\":\"1000000000\","
    "\"rate_per_minute\":3},"
    "\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"1000000000000000000\",\"label\":\"treasury\"}],"
    "\"contracts\":["
    " {\"address\":\"" USDC "\",\"label\":\"usdc\",\"max_value\":\"0\",\"rules\":["
    "   {\"name\":\"approve-permit2\",\"calldata\":\"^095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3[0-9a-f]{64}$\"},"
    "   {\"name\":\"transfer-self\",\"calldata\":\"^a9059cbb{{addr:self}}[0-9a-f]{64}$\"}]},"
    " {\"address\":\"" ROUTER "\",\"label\":\"router\",\"max_value\":\"0\",\"rules\":["
    "   {\"name\":\"any-execute\",\"calldata\":\"^3593564c([0-9a-f]{64})*$\"}]}"
    "]}";

static eth_tx_t *mktx(const char *to, const char *datahex, const char *value_dec)
{
    eth_tx_t *tx = calloc(1, sizeof(eth_tx_t));
    tx->type = ETH_TX_TYPE_EIP1559;
    tx->chain_id = 8453;
    tx->nonce = 1;
    tx->gas = 100000;
    u256_from_dec("1000000000", tx->max_fee);
    u256_from_dec("1000000", tx->max_prio);
    if (to) {
        tx->has_to = 1;
        addr_from_hex(to, tx->to);
    }
    u256_from_dec(value_dec ? value_dec : "0", tx->value);
    if (datahex) tx->data_len = (size_t)hex_decode(datahex, tx->data, ETH_TX_MAX_DATA);
    return tx;
}

static void expect(policy_t *p, eth_tx_t *tx, uint64_t now, int allowed, const char *needle)
{
    policy_result_t r;
    policy_check(p, tx, now, &r);
    CHECK(r.allowed == allowed && strstr(r.reason, needle), "allowed=%d reason='%s' (want %d '%s')", r.allowed,
          r.reason, allowed, needle);
    free(tx);
}

static const char *word(const char *addr)
{
    static char buf[65];
    memset(buf, '0', 24);
    memcpy(buf + 24, addr + 2, 40);
    buf[64] = 0;
    return buf;
}

static void test_policy_eval(void)
{
    uint8_t self[20];
    addr_from_hex(SELF, self);
    policy_t *p;
    char err[160];
    int rc = policy_load(POLICY_JSON, strlen(POLICY_JSON), self, &p, err, sizeof(err));
    CHECK(rc == 0, "load: %s", err);
    if (rc) return;

    char data[512];
    const char *max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    uint64_t t = 1000;

    snprintf(data, sizeof(data), "0x095ea7b3%s%s", word(PERMIT2), max);
    expect(p, mktx(USDC, data, NULL), t, 1, "usdc:approve-permit2");

    snprintf(data, sizeof(data), "0x095ea7b3%s%s", word(EVIL), max);
    expect(p, mktx(USDC, data, NULL), t, 0, "matched no rule");

    snprintf(data, sizeof(data), "0x095ea7b3%s%s00", word(PERMIT2), max); /* trailing bytes */
    expect(p, mktx(USDC, data, NULL), t, 0, "matched no rule");

    snprintf(data, sizeof(data), "0xa9059cbb%s%s", word(SELF), max);
    expect(p, mktx(USDC, data, NULL), t, 1, "transfer-self");
    expect(p, mktx(USDC, data, NULL), t, 1, "transfer-self");

    /* rate limit: 3/min, three allowed above consumed all tokens (rejections don't consume) */
    snprintf(data, sizeof(data), "0xa9059cbb%s%s", word(SELF), max);
    expect(p, mktx(USDC, data, NULL), t, 0, "rate limit");
    /* 20s later one token has refilled */
    expect(p, mktx(USDC, data, NULL), t + 20000, 1, "transfer-self");

    t += 600000; /* refill */
    snprintf(data, sizeof(data), "0xa9059cbb%s%s", word(EVIL), max);
    expect(p, mktx(USDC, data, NULL), t, 0, "selector 0xa9059cbb");

    expect(p, mktx(USDC, NULL, NULL), t, 0, "matched no rule"); /* empty calldata to contract */
    expect(p, mktx(USDC, data, "1"), t, 0, "exceeds max_value");

    expect(p, mktx(TREASURY, NULL, "1000000000000000000"), t, 1, "native_transfer:treasury");
    expect(p, mktx(TREASURY, NULL, "1000000000000000001"), t, 0, "exceeds max_value");
    expect(p, mktx(TREASURY, "0x00", NULL), t, 0, "not whitelisted"); /* data to native-only addr */
    expect(p, mktx(EVIL, NULL, "1"), t + 60000, 0, "native transfer to");
    expect(p, mktx(EVIL, "0x12345678", NULL), t + 120000, 0, "destination");
    expect(p, mktx(NULL, "0x6080", NULL), t, 0, "contract creation");

    eth_tx_t *tx = mktx(ROUTER, "0x3593564c", NULL);
    tx->chain_id = 1;
    expect(p, tx, t, 0, "chainId 1");

    tx = mktx(ROUTER, "0x3593564c", NULL);
    tx->gas = 3000001;
    expect(p, tx, t, 0, "max_gas");

    tx = mktx(ROUTER, "0x3593564c", NULL);
    u256_from_dec("5000000001", tx->max_fee);
    expect(p, tx, t, 0, "fee per gas");

    tx = mktx(ROUTER, "0x3593564c", NULL);
    u256_from_dec("1000000001", tx->max_prio);
    expect(p, tx, t, 0, "priority fee");

    tx = mktx(ROUTER, "0x3593564c", NULL);
    tx->type = ETH_TX_TYPE_LEGACY;
    u256_from_dec("5000000001", tx->gas_price);
    expect(p, tx, t + 300000, 0, "fee per gas");

    tx = mktx(ROUTER, "0x3593564c", NULL);
    tx->type = 4;
    expect(p, tx, t, 0, "type 0x4");

    expect(p, mktx(ROUTER, "0x3593564c", NULL), t + 400000, 1, "router:any-execute");

    policy_free(p);
}


/* Two chains: Base (8453) with tight fees, Celo (42220) with high fees. USDC is only
 * whitelisted on Base; ROUTER has different rules on each chain. */
static const char *MULTI_JSON =
    "{\"version\":1,\"chain_ids\":[8453,42220],"
    "\"limits\":{\"max_gas\":1000000,\"max_fee_per_gas\":\"1000000000\",\"max_priority_fee_per_gas\":\"1000000\","
    "\"rate_per_minute\":0},"
    "\"chain_limits\":[{\"chain_id\":42220,\"max_gas\":2000000,\"max_fee_per_gas\":\"100000000000\","
    "\"max_priority_fee_per_gas\":\"5000000000\"}],"
    "\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"5\",\"chain_ids\":[42220]}],"
    "\"contracts\":["
    " {\"address\":\"" USDC "\",\"max_value\":\"0\",\"chain_ids\":[8453],\"rules\":["
    "   {\"name\":\"approve\",\"calldata\":\"^095ea7b3[0-9a-f]{128}$\"}]},"
    " {\"address\":\"" ROUTER "\",\"label\":\"router-base\",\"max_value\":\"0\",\"chain_ids\":[8453],\"rules\":["
    "   {\"name\":\"a\",\"calldata\":\"^aaaaaaaa$\"}]},"
    " {\"address\":\"" ROUTER "\",\"label\":\"router-celo\",\"max_value\":\"0\",\"chain_ids\":[42220],\"rules\":["
    "   {\"name\":\"b\",\"calldata\":\"^bbbbbbbb$\"}]}"
    "]}";

static eth_tx_t *on_chain(eth_tx_t *tx, uint64_t chain, const char *max_fee)
{
    tx->chain_id = chain;
    if (max_fee) u256_from_dec(max_fee, tx->max_fee);
    return tx;
}

static void test_policy_multichain(void)
{
    policy_t *p;
    char err[160];
    int rc = policy_load(MULTI_JSON, strlen(MULTI_JSON), NULL, &p, err, sizeof(err));
    CHECK(rc == 0, "load multi: %s", err);
    if (rc) return;
    char data[300];
    snprintf(data, sizeof(data), "0x095ea7b3%s%s", word(PERMIT2), word(PERMIT2));

    /* Per-chain fee caps: 30 gwei is fine on Celo, rejected on Base. */
    expect(p, on_chain(mktx(ROUTER, "0xbbbbbbbb", NULL), 42220, "30000000000"), 0, 1, "router-celo:b");
    expect(p, on_chain(mktx(ROUTER, "0xaaaaaaaa", NULL), 8453, "30000000000"), 0, 0, "fee per gas");
    expect(p, on_chain(mktx(ROUTER, "0xaaaaaaaa", NULL), 8453, "1000000000"), 0, 1, "router-base:a");
    eth_tx_t *tx = on_chain(mktx(ROUTER, "0xbbbbbbbb", NULL), 42220, "30000000000");
    tx->gas = 1500000; /* above global max_gas, below Celo's */
    expect(p, tx, 0, 1, "router-celo");
    tx = on_chain(mktx(ROUTER, "0xbbbbbbbb", NULL), 42220, "100000000001");
    expect(p, tx, 0, 0, "fee per gas");

    /* Same address, rules depend on the chain. */
    expect(p, on_chain(mktx(ROUTER, "0xbbbbbbbb", NULL), 8453, NULL), 0, 0, "matched no rule for contract router-base");
    expect(p, on_chain(mktx(ROUTER, "0xaaaaaaaa", NULL), 42220, NULL), 0, 0, "matched no rule for contract router-celo");

    /* Entries restricted to the other chain do not exist on this one. */
    expect(p, on_chain(mktx(USDC, data, NULL), 8453, NULL), 0, 1, "approve");
    expect(p, on_chain(mktx(USDC, data, NULL), 42220, NULL), 0, 0, "destination");
    expect(p, on_chain(mktx(TREASURY, NULL, "5"), 42220, NULL), 0, 1, "native_transfer");
    expect(p, on_chain(mktx(TREASURY, NULL, "5"), 8453, NULL), 0, 0, "not whitelisted");
    policy_free(p);
}

static void load_bad(const char *json, const char *needle, int with_self)
{
    uint8_t self[20];
    addr_from_hex(SELF, self);
    policy_t *p = NULL;
    char err[200] = "";
    int rc = policy_load(json, strlen(json), with_self ? self : NULL, &p, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, needle), "err='%s' want '%s'", err, needle);
    policy_free(p);
}

#define LIM "\"limits\":{\"max_gas\":1,\"max_fee_per_gas\":\"1\",\"max_priority_fee_per_gas\":\"1\"}"

static void test_policy_load(void)
{
    load_bad("not json", "not valid JSON", 1);
    load_bad("{\"version\":2,\"chain_ids\":[1]," LIM "}", "version", 1);
    load_bad("{\"version\":1,\"chain_ids\":[]," LIM "}", "chain_ids", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"extra\":1}", "unknown key 'extra'", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM "}", "allows nothing", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1],\"limits\":{\"max_gas\":1,\"max_fee_per_gas\":1,\"max_priority_fee_per_gas\":\"1\"}}",
             "decimal wei", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"095ea7b3.*$\"}]}]}",
             "must start with ^", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"^095ea7b3.*\\\\$\"}]}]}",
             "must start with ^", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"^a9059cbb{{addr:self}}$\"}]}]}",
             "unexpanded macro", 0);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"^{{addr:usdc}}$\"}]}]}",
             "unexpanded macro", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"^(ab$\"}]}]}",
             "regex error", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"contracts\":[{\"address\":\"" USDC
             "\",\"max_value\":\"0\",\"rules\":[]}]}",
             "non-empty", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"native_transfers\":[{\"to\":\"" TREASURY
             "\",\"max_value\":\"0\"},{\"to\":\"" TREASURY "\",\"max_value\":\"0\"}]}",
             "duplicate", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"native_transfers\":[{\"to\":\"{{self}}\",\"max_value\":\"0\"}]}",
             "no signer key", 0);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"native_transfers\":[{\"to\":\"0x12\",\"max_value\":\"0\"}]}",
             "invalid address", 1);

    /* per-chain scoping */
    load_bad("{\"version\":1,\"chain_ids\":[1,1]," LIM ",\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"0\"}]}",
             "duplicate chain", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1,2]," LIM ",\"native_transfers\":["
             "{\"to\":\"" TREASURY "\",\"max_value\":\"0\",\"chain_ids\":[1,2]},"
             "{\"to\":\"" TREASURY "\",\"max_value\":\"0\",\"chain_ids\":[2]}]}",
             "duplicate address on the same chain", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1,2]," LIM ",\"contracts\":["
             "{\"address\":\"" USDC "\",\"max_value\":\"0\",\"rules\":[{\"calldata\":\"^00$\"}]},"
             "{\"address\":\"" USDC "\",\"max_value\":\"0\",\"chain_ids\":[2],\"rules\":[{\"calldata\":\"^00$\"}]}]}",
             "duplicate address on the same chain", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"native_transfers\":[{\"to\":\"" TREASURY
             "\",\"max_value\":\"0\",\"chain_ids\":[5]}]}",
             "not in the policy's chain_ids", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"native_transfers\":[{\"to\":\"" TREASURY
             "\",\"max_value\":\"0\",\"chain_ids\":[]}]}",
             "non-empty", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"chain_limits\":[{\"chain_id\":5,\"max_gas\":1,"
             "\"max_fee_per_gas\":\"1\",\"max_priority_fee_per_gas\":\"1\"}],"
             "\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"0\"}]}",
             "not in chain_ids", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"chain_limits\":[{\"chain_id\":1,\"max_gas\":1}],"
             "\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"0\"}]}",
             "missing 'max_fee_per_gas'", 1);
    load_bad("{\"version\":1,\"chain_ids\":[1]," LIM ",\"chain_limits\":[{\"chain_id\":1,\"max_gas\":1,"
             "\"max_fee_per_gas\":\"1\",\"max_priority_fee_per_gas\":\"1\",\"rate_per_minute\":1}],"
             "\"native_transfers\":[{\"to\":\"" TREASURY "\",\"max_value\":\"0\"}]}",
             "unknown key 'rate_per_minute'", 1);
}

int main(void)
{
    test_regex();
    test_policy_eval();
    test_policy_multichain();
    test_policy_load();
    DONE();
}
