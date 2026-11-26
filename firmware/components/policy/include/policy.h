#pragma once
#include "eth_tx.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POLICY_MAX_CHAIN_IDS 16
#define POLICY_MAX_NATIVE 64
#define POLICY_MAX_CONTRACTS 128
#define POLICY_MAX_RULES_PER_CONTRACT 64
#ifndef POLICY_MAX_TOTAL_INSTS
#define POLICY_MAX_TOTAL_INSTS 16384 /* ~128 KB of compiled regex */
#endif

typedef struct policy policy_t;

typedef struct {
    int allowed;
    char reason[160]; /* why rejected, or the matched rule on allow */
} policy_result_t;

/*
 * Parse and compile a canonical-JSON policy (see docs/POLICY.md).
 * `self_addr` (may be NULL if no key yet) replaces {{self}} / {{addr:self}}.
 * Strict: unknown keys, duplicates, unanchored regexes and invalid values are
 * rejected. Returns 0 or -1 with `err` set.
 */
int policy_load(const char *json, size_t len, const uint8_t *self_addr, policy_t **out, char *err, size_t errlen);
void policy_free(policy_t *p);

/* Default-deny evaluation. `now_ms` drives the rate limiter, which only
 * consumes a token when every other check has passed. Not reentrant: it uses
 * scratch memory owned by `p`, so callers serialize (signer mode holds a mutex). */
void policy_check(policy_t *p, const eth_tx_t *tx, uint64_t now_ms, policy_result_t *res);

size_t policy_total_insts(const policy_t *p);

#ifdef __cplusplus
}
#endif
