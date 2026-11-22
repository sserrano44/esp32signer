#include "hex.h"
#include "keccak256.h"
#include <string.h>

int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char *skip_0x(const char *s)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return s + 2;
    return s;
}

int hex_decode(const char *s, uint8_t *out, size_t out_cap)
{
    if (!s) return -1;
    s = skip_0x(s);
    size_t n = strlen(s);
    if (n % 2) return -1;
    if (n / 2 > out_cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(s[2 * i]), lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0xf];
    }
    out[2 * len] = 0;
}

int u256_from_hex(const char *s, uint8_t out[32])
{
    memset(out, 0, 32);
    if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    s += 2;
    size_t n = strlen(s);
    if (n == 0) return -1;
    while (n > 1 && *s == '0') { s++; n--; } /* tolerate leading zeros */
    if (n > 64) return -1;
    for (size_t i = 0; i < n; i++) {
        int v = hex_nibble(s[n - 1 - i]);
        if (v < 0) return -1;
        out[31 - i / 2] |= (uint8_t)(v << ((i % 2) * 4));
    }
    return 0;
}

int u256_from_dec(const char *s, uint8_t out[32])
{
    memset(out, 0, 32);
    if (!s || !*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        /* out = out*10 + digit */
        unsigned carry = (unsigned)(*s - '0');
        for (int i = 31; i >= 0; i--) {
            unsigned v = out[i] * 10u + carry;
            out[i] = (uint8_t)v;
            carry = v >> 8;
        }
        if (carry) return -1;
    }
    return 0;
}

void u256_from_u64(uint64_t v, uint8_t out[32])
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

int u256_to_u64(const uint8_t v[32], uint64_t *out)
{
    for (int i = 0; i < 24; i++)
        if (v[i]) return -1;
    uint64_t r = 0;
    for (int i = 24; i < 32; i++) r = (r << 8) | v[i];
    *out = r;
    return 0;
}

int u256_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

int u256_is_zero(const uint8_t v[32])
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= v[i];
    return acc == 0;
}

void u256_to_dec(const uint8_t v[32], char *out)
{
    uint8_t tmp[32];
    char buf[80];
    int pos = 79;
    memcpy(tmp, v, 32);
    buf[pos] = 0;
    do {
        unsigned rem = 0;
        for (int i = 0; i < 32; i++) {
            unsigned cur = (rem << 8) | tmp[i];
            tmp[i] = (uint8_t)(cur / 10);
            rem = cur % 10;
        }
        buf[--pos] = (char)('0' + rem);
    } while (!u256_is_zero(tmp));
    strcpy(out, &buf[pos]);
}

int addr_from_hex(const char *s, uint8_t out[20])
{
    if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    if (strlen(s) != 42) return -1;
    return hex_decode(s, out, 20) == 20 ? 0 : -1;
}

void addr_to_hex(const uint8_t a[20], char *out)
{
    out[0] = '0';
    out[1] = 'x';
    hex_encode(a, 20, out + 2);
}

void addr_to_checksum_hex(const uint8_t a[20], char *out)
{
    char lower[41];
    uint8_t h[32];
    hex_encode(a, 20, lower);
    keccak256((const uint8_t *)lower, 40, h);
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 40; i++) {
        char c = lower[i];
        int nib = (h[i / 2] >> (i % 2 ? 0 : 4)) & 0xf;
        if (c >= 'a' && nib >= 8) c = (char)(c - 'a' + 'A');
        out[2 + i] = c;
    }
    out[42] = 0;
}
