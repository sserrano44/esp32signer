#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal linear-time regex (Thompson NFA / Pike VM, no backtracking).
 *
 * Supported: literals, '.', [abc] [a-z] [^...], (...), (?:...), |, * + ?,
 * {n} {n,} {n,m} (m <= REGEX_MAX_REPEAT), ^ $, escapes \. \\ \d etc.
 *
 * Matching is always FULL-string: a program only matches if it consumes the
 * entire input. ^ and $ are accepted (and required by the policy loader) but
 * a pattern can never match a substring.
 */

#define REGEX_MAX_INSTS 8192
#define REGEX_MAX_REPEAT 1024
#define REGEX_STEP_BUDGET 8000000u

typedef struct regex_prog regex_prog_t;

int regex_compile(const char *pattern, regex_prog_t **out, char *err, size_t errlen);
/* 1 = match, 0 = no match, -1 = step budget exceeded / OOM (treat as deny). */
int regex_full_match(const regex_prog_t *p, const char *s, size_t len);
size_t regex_prog_insts(const regex_prog_t *p);
void regex_free(regex_prog_t *p);

#ifdef __cplusplus
}
#endif
