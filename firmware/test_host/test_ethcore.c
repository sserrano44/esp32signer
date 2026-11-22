#include "cJSON.h"
#include "eth_signer.h"
#include "eth_tx.h"
#include "hex.h"
#include "keccak256.h"
#include "rlp.h"
#include "test_util.h"
#include <strings.h>

static void test_rlp(void)
{
    uint8_t buf[256];
    char hex[513];
    rlp_buf_t r;

    rlp_init(&r, buf, sizeof(buf));
    rlp_put_bytes(&r, (const uint8_t *)"dog", 3);
    hex_encode(buf, r.len, hex);
    CHECK(!strcmp(hex, "83646f67"), "%s", hex);

    rlp_init(&r, buf, sizeof(buf));
    size_t l = rlp_list_begin(&r);
    rlp_put_bytes(&r, (const uint8_t *)"cat", 3);
    rlp_put_bytes(&r, (const uint8_t *)"dog", 3);
    rlp_list_end(&r, l);
    hex_encode(buf, r.len, hex);
    CHECK(!strcmp(hex, "c88363617483646f67"), "%s", hex);

    rlp_init(&r, buf, sizeof(buf));
    rlp_put_u64(&r, 0);
    rlp_put_u64(&r, 15);
    rlp_put_u64(&r, 1024);
    rlp_put_bytes(&r, NULL, 0);
    l = rlp_list_begin(&r);
    rlp_list_end(&r, l);
    hex_encode(buf, r.len, hex);
    CHECK(!strcmp(hex, "800f82040080c0"), "%s", hex);

    const char *lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit";
    rlp_init(&r, buf, sizeof(buf));
    rlp_put_bytes(&r, (const uint8_t *)lorem, strlen(lorem));
    CHECK(r.len == 58 && buf[0] == 0xb8 && buf[1] == 56, "len=%zu", r.len);

    /* overflow is sticky */
    rlp_init(&r, buf, 3);
    rlp_put_bytes(&r, (const uint8_t *)"dog", 3);
    CHECK(r.err == 1, "expected overflow");
}

static void test_hex(void)
{
    uint8_t v[32], w[32];
    char dec[80];
    CHECK(u256_from_hex("0x0", v) == 0 && u256_is_zero(v), "0x0");
    CHECK(u256_from_hex("0x", v) != 0, "empty");
    CHECK(u256_from_hex("12", v) != 0, "no prefix");
    CHECK(u256_from_hex("0x00ff", v) == 0 && v[31] == 0xff && v[30] == 0, "leading zeros");
    CHECK(u256_from_hex("0x1" "0000000000000000000000000000000000000000000000000000000000000000", v) != 0, "overflow");
    CHECK(u256_from_dec("115792089237316195423570985008687907853269984665640564039457584007913129639935", v) == 0, "max");
    for (int i = 0; i < 32; i++) CHECK(v[i] == 0xff, "max byte %d", i);
    CHECK(u256_from_dec("115792089237316195423570985008687907853269984665640564039457584007913129639936", v) != 0,
          "dec overflow");
    CHECK(u256_from_dec("5000000000", v) == 0, "5 gwei");
    u256_to_dec(v, dec);
    CHECK(!strcmp(dec, "5000000000"), "%s", dec);
    u256_from_u64(5000000000ULL, w);
    CHECK(u256_cmp(v, w) == 0, "u64 roundtrip");
    CHECK(u256_from_dec("12a", v) != 0, "bad digit");

    uint8_t a[20];
    char cs[43];
    CHECK(addr_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", a) == 0, "addr");
    addr_to_checksum_hex(a, cs);
    CHECK(!strcmp(cs, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), "%s", cs);
    CHECK(addr_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae", a) != 0, "short addr");
}

static void test_keccak(cJSON *arr)
{
    cJSON *v;
    cJSON_ArrayForEach(v, arr)
    {
        const char *in = cJSON_GetObjectItem(v, "in")->valuestring;
        const char *out = cJSON_GetObjectItem(v, "out")->valuestring;
        size_t n = strlen(in) / 2;
        uint8_t *buf = malloc(n + 1);
        hex_decode(in, buf, n);
        uint8_t h[32];
        char hx[65];
        keccak256(buf, n, h);
        hex_encode(h, 32, hx);
        CHECK(!strcmp(hx, out), "keccak len %zu: %s != %s", n, hx, out);
        /* streaming in odd chunks */
        keccak256_ctx_t ctx;
        keccak256_init(&ctx);
        for (size_t i = 0; i < n; i += 7) keccak256_update(&ctx, buf + i, (n - i) < 7 ? (n - i) : 7);
        keccak256_final(&ctx, h);
        hex_encode(h, 32, hx);
        CHECK(!strcmp(hx, out), "keccak stream len %zu", n);
        free(buf);
    }
}

static void test_sign(cJSON *arr)
{
    eth_tx_t *tx = malloc(sizeof(eth_tx_t));
    uint8_t *raw = malloc(ETH_TX_MAX_ENCODED);
    char *rawhex = malloc(ETH_TX_MAX_ENCODED * 2 + 3);
    int i = 0;
    cJSON *v;
    cJSON_ArrayForEach(v, arr)
    {
        uint8_t key[32], addr[20], txhash[32];
        char err[128], cs[43], hh[67];
        hex_decode(cJSON_GetObjectItem(v, "key")->valuestring, key, 32);
        CHECK(eth_privkey_valid(key), "key valid #%d", i);
        CHECK(eth_address_from_privkey(key, addr) == 0, "addr #%d", i);
        addr_to_checksum_hex(addr, cs);
        CHECK(!strcmp(cs, cJSON_GetObjectItem(v, "address")->valuestring), "address #%d %s", i, cs);

        int rc = eth_tx_from_json(cJSON_GetObjectItem(v, "tx"), tx, err, sizeof(err));
        CHECK(rc == 0, "parse #%d: %s", i, err);
        if (rc == 0) {
            size_t len = 0;
            CHECK(eth_tx_sign(tx, key, raw, ETH_TX_MAX_ENCODED, &len, txhash) == 0, "sign #%d", i);
            rawhex[0] = '0';
            rawhex[1] = 'x';
            hex_encode(raw, len, rawhex + 2);
            CHECK(!strcmp(rawhex, cJSON_GetObjectItem(v, "raw")->valuestring), "raw #%d\n got %.80s...\nwant %.80s...",
                  i, rawhex, cJSON_GetObjectItem(v, "raw")->valuestring);
            hh[0] = '0';
            hh[1] = 'x';
            hex_encode(txhash, 32, hh + 2);
            CHECK(!strcmp(hh, cJSON_GetObjectItem(v, "hash")->valuestring), "hash #%d", i);
        }
        i++;
    }
    free(tx);
    free(raw);
    free(rawhex);
}

static void expect_parse_error(const char *json, const char *needle)
{
    eth_tx_t *tx = malloc(sizeof(eth_tx_t));
    char err[160] = "";
    cJSON *o = cJSON_Parse(json);
    int rc = eth_tx_from_json(o, tx, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, needle), "json=%s err='%s' want '%s'", json, err, needle);
    cJSON_Delete(o);
    free(tx);
}

static void test_parse_errors(void)
{
    const char *base = "\"chainId\":\"0x2105\",\"nonce\":\"0x0\",\"gas\":\"0x5208\",\"to\":\"0x1111111111111111111111111111111111111111\"";
    char buf[512];
    snprintf(buf, sizeof(buf), "{%s,\"type\":\"0x4\",\"maxFeePerGas\":\"0x1\",\"maxPriorityFeePerGas\":\"0x1\"}", base);
    expect_parse_error(buf, "unsupported transaction type");
    snprintf(buf, sizeof(buf), "{%s,\"type\":\"0x1\",\"gasPrice\":\"0x1\"}", base);
    expect_parse_error(buf, "unsupported transaction type");
    snprintf(buf, sizeof(buf), "{%s,\"maxFeePerGas\":\"0x1\",\"maxPriorityFeePerGas\":\"0x1\",\"authorizationList\":[]}", base);
    expect_parse_error(buf, "authorizationList");
    snprintf(buf, sizeof(buf), "{%s}", base);
    expect_parse_error(buf, "missing fee");
    expect_parse_error("{\"nonce\":\"0x0\",\"gas\":\"0x5208\",\"gasPrice\":\"0x1\"}", "chainId");
    expect_parse_error("{\"chainId\":\"0x1\",\"gas\":\"0x5208\",\"gasPrice\":\"0x1\"}", "nonce");
    expect_parse_error("{\"chainId\":\"0x1\",\"nonce\":\"0x1\",\"gasPrice\":\"0x1\"}", "gas");
    snprintf(buf, sizeof(buf), "{%s,\"maxFeePerGas\":\"0x1\",\"maxPriorityFeePerGas\":\"0x2\"}", base);
    expect_parse_error(buf, "exceeds maxFeePerGas");
    snprintf(buf, sizeof(buf), "{%s,\"gasPrice\":\"0x1\",\"data\":\"0x00\",\"input\":\"0x01\"}", base);
    expect_parse_error(buf, "differ");
    snprintf(buf, sizeof(buf), "{%s,\"gasPrice\":\"0x1\",\"data\":\"0x0\"}", base);
    expect_parse_error(buf, "data");
    expect_parse_error("{\"chainId\":\"0x1\",\"nonce\":\"0x1\",\"gas\":\"0x1\",\"gasPrice\":\"0x1\",\"to\":\"0x12\"}", "'to'");
}

int main(int argc, char **argv)
{
    uint8_t seed[32] = {1, 2, 3};
    CHECK(eth_signer_init(seed) == 0, "init");
    test_rlp();
    test_hex();
    test_parse_errors();
    if (argc > 1) {
        char *json = read_file(argv[1], NULL);
        CHECK(json != NULL, "read %s", argv[1]);
        if (json) {
            cJSON *root = cJSON_Parse(json);
            test_keccak(cJSON_GetObjectItem(root, "keccak"));
            test_sign(cJSON_GetObjectItem(root, "sign"));
            cJSON_Delete(root);
            free(json);
        }
    }
    eth_signer_deinit();
    DONE();
}
