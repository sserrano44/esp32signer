#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Append-only RLP encoder into a caller-provided buffer. Errors are sticky:
 * once `err` is set every further call is a no-op. */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int err;
} rlp_buf_t;

void rlp_init(rlp_buf_t *r, uint8_t *buf, size_t cap);
void rlp_put_raw(rlp_buf_t *r, const uint8_t *data, size_t len);
void rlp_put_bytes(rlp_buf_t *r, const uint8_t *data, size_t len);
/* Big-endian integer; leading zero bytes are stripped (0 -> 0x80). */
void rlp_put_uint_be(rlp_buf_t *r, const uint8_t *be, size_t len);
void rlp_put_u64(rlp_buf_t *r, uint64_t v);
/* Returns a marker to pass to rlp_list_end. */
size_t rlp_list_begin(rlp_buf_t *r);
void rlp_list_end(rlp_buf_t *r, size_t marker);

#ifdef __cplusplus
}
#endif
