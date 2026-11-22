#include "rlp.h"
#include <string.h>

void rlp_init(rlp_buf_t *r, uint8_t *buf, size_t cap)
{
    r->buf = buf;
    r->cap = cap;
    r->len = 0;
    r->err = 0;
}

void rlp_put_raw(rlp_buf_t *r, const uint8_t *data, size_t len)
{
    if (r->err) return;
    if (r->cap - r->len < len) {
        r->err = 1;
        return;
    }
    if (len) memcpy(r->buf + r->len, data, len);
    r->len += len;
}

/* Encode a length header with given short-form offset (0x80 strings, 0xc0 lists). */
static size_t header(uint8_t *out, size_t len, uint8_t offset)
{
    if (len <= 55) {
        out[0] = (uint8_t)(offset + len);
        return 1;
    }
    uint8_t tmp[8];
    int n = 0;
    for (size_t v = len; v; v >>= 8) tmp[n++] = (uint8_t)v;
    out[0] = (uint8_t)(offset + 55 + n);
    for (int i = 0; i < n; i++) out[1 + i] = tmp[n - 1 - i];
    return 1 + (size_t)n;
}

void rlp_put_bytes(rlp_buf_t *r, const uint8_t *data, size_t len)
{
    if (len == 1 && data[0] < 0x80) {
        rlp_put_raw(r, data, 1);
        return;
    }
    uint8_t h[9];
    size_t hl = header(h, len, 0x80);
    rlp_put_raw(r, h, hl);
    rlp_put_raw(r, data, len);
}

void rlp_put_uint_be(rlp_buf_t *r, const uint8_t *be, size_t len)
{
    while (len && *be == 0) {
        be++;
        len--;
    }
    rlp_put_bytes(r, be, len);
}

void rlp_put_u64(rlp_buf_t *r, uint64_t v)
{
    uint8_t be[8];
    for (int i = 0; i < 8; i++) be[7 - i] = (uint8_t)(v >> (8 * i));
    rlp_put_uint_be(r, be, 8);
}

size_t rlp_list_begin(rlp_buf_t *r)
{
    return r->len;
}

void rlp_list_end(rlp_buf_t *r, size_t marker)
{
    if (r->err) return;
    size_t payload = r->len - marker;
    uint8_t h[9];
    size_t hl = header(h, payload, 0xc0);
    if (r->cap - r->len < hl) {
        r->err = 1;
        return;
    }
    memmove(r->buf + marker + hl, r->buf + marker, payload);
    memcpy(r->buf + marker, h, hl);
    r->len += hl;
}
