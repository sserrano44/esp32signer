#include "regex.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- AST --- */

enum { N_EMPTY, N_CHAR, N_STR, N_ANY, N_CLASS, N_BOL, N_EOL, N_CAT, N_ALT, N_REP };

typedef struct {
    uint8_t type;
    uint8_t c;
    uint16_t cls;
    int a, b;          /* children (CAT/ALT), child in a (REP), offset/length into the pattern (STR) */
    int16_t min, max;  /* REP; max == -1 for unbounded (<= REGEX_MAX_REPEAT) */
} node_t;

typedef struct {
    uint32_t bits[8];
} cls_t;

typedef struct {
    const char *p;
    const char *start; /* the whole pattern: N_STR nodes point into it */
    node_t *nodes;
    int n_nodes, cap_nodes;
    cls_t *classes;
    int n_classes, cap_classes;
    int depth;
    char *err;
    size_t errlen;
    int failed;
} parser_t;

static int perr(parser_t *ps, const char *fmt, ...)
{
    if (!ps->failed && ps->err && ps->errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(ps->err, ps->errlen, fmt, ap);
        va_end(ap);
    }
    ps->failed = 1;
    return -1;
}

static int new_node(parser_t *ps, uint8_t type)
{
    if (ps->n_nodes == ps->cap_nodes) {
        int nc = ps->cap_nodes ? ps->cap_nodes * 2 : 64;
        if (nc > 65536) return perr(ps, "pattern too complex");
        node_t *n = realloc(ps->nodes, (size_t)nc * sizeof(node_t));
        if (!n) return perr(ps, "out of memory");
        ps->nodes = n;
        ps->cap_nodes = nc;
    }
    node_t *n = &ps->nodes[ps->n_nodes];
    memset(n, 0, sizeof(*n));
    n->type = type;
    n->a = n->b = -1;
    return ps->n_nodes++;
}

static int add_class(parser_t *ps, const cls_t *c)
{
    for (int i = 0; i < ps->n_classes; i++)
        if (!memcmp(&ps->classes[i], c, sizeof(cls_t))) return i;
    if (ps->n_classes == ps->cap_classes) {
        int nc = ps->cap_classes ? ps->cap_classes * 2 : 8;
        if (nc > 4096) return perr(ps, "too many character classes");
        cls_t *n = realloc(ps->classes, (size_t)nc * sizeof(cls_t));
        if (!n) return perr(ps, "out of memory");
        ps->classes = n;
        ps->cap_classes = nc;
    }
    ps->classes[ps->n_classes] = *c;
    return ps->n_classes++;
}

static void cls_set(cls_t *c, unsigned ch)
{
    c->bits[ch >> 5] |= 1u << (ch & 31);
}

static void cls_range(cls_t *c, unsigned lo, unsigned hi)
{
    for (unsigned ch = lo; ch <= hi; ch++) cls_set(c, ch);
}

/* Shorthand escapes \d \w \s into a class. Returns 1 if handled. */
static int shorthand(char e, cls_t *c)
{
    switch (e) {
    case 'd': cls_range(c, '0', '9'); return 1;
    case 'w': cls_range(c, '0', '9'); cls_range(c, 'a', 'z'); cls_range(c, 'A', 'Z'); cls_set(c, '_'); return 1;
    case 's': cls_set(c, ' '); cls_set(c, '\t'); cls_set(c, '\n'); cls_set(c, '\r'); cls_set(c, '\f'); cls_set(c, '\v'); return 1;
    default: return 0;
    }
}

static int is_meta(char c)
{
    return c && strchr(".[]()|*+?{}^$\\-/", c) != NULL;
}

static int parse_alt(parser_t *ps);

static int parse_class(parser_t *ps)
{
    cls_t c;
    memset(&c, 0, sizeof(c));
    int neg = 0;
    ps->p++; /* '[' */
    if (*ps->p == '^') {
        neg = 1;
        ps->p++;
    }
    int first = 1;
    while (*ps->p && (*ps->p != ']' || first)) {
        unsigned lo;
        if (*ps->p == '\\') {
            char e = ps->p[1];
            if (!e) return perr(ps, "trailing backslash");
            ps->p += 2;
            if (shorthand(e, &c)) {
                first = 0;
                continue;
            }
            if (!is_meta(e)) return perr(ps, "unsupported escape \\%c", e);
            lo = (unsigned char)e;
        } else {
            lo = (unsigned char)*ps->p++;
        }
        unsigned hi = lo;
        if (ps->p[0] == '-' && ps->p[1] && ps->p[1] != ']') {
            ps->p++;
            if (*ps->p == '\\') {
                char e = ps->p[1];
                if (!e || !is_meta(e)) return perr(ps, "bad range escape");
                hi = (unsigned char)e;
                ps->p += 2;
            } else {
                hi = (unsigned char)*ps->p++;
            }
            if (hi < lo) return perr(ps, "bad character range");
        }
        cls_range(&c, lo, hi);
        first = 0;
    }
    if (*ps->p != ']') return perr(ps, "unterminated character class");
    ps->p++;
    if (neg)
        for (int i = 0; i < 8; i++) c.bits[i] = ~c.bits[i];
    int idx = add_class(ps, &c);
    if (idx < 0) return -1;
    int n = new_node(ps, N_CLASS);
    if (n < 0) return -1;
    ps->nodes[n].cls = (uint16_t)idx;
    return n;
}

static int parse_int(parser_t *ps, int *out)
{
    int v = 0, digits = 0;
    while (*ps->p >= '0' && *ps->p <= '9') {
        v = v * 10 + (*ps->p++ - '0');
        if (v > REGEX_MAX_REPEAT) return perr(ps, "repeat count exceeds %d", REGEX_MAX_REPEAT);
        digits++;
    }
    if (!digits) return perr(ps, "expected number in {}");
    *out = v;
    return 0;
}

static int parse_atom(parser_t *ps)
{
    char ch = *ps->p;
    int n;
    switch (ch) {
    case '(':
        if (++ps->depth > 64) return perr(ps, "groups nested too deeply");
        ps->p++;
        if (ps->p[0] == '?') {
            if (ps->p[1] != ':') return perr(ps, "only (?:...) groups are supported");
            ps->p += 2;
        }
        n = parse_alt(ps);
        if (n < 0) return -1;
        if (*ps->p != ')') return perr(ps, "missing )");
        ps->p++;
        ps->depth--;
        return n;
    case '[':
        return parse_class(ps);
    case '.':
        ps->p++;
        return new_node(ps, N_ANY);
    case '^':
        ps->p++;
        return new_node(ps, N_BOL);
    case '$':
        ps->p++;
        return new_node(ps, N_EOL);
    case '\\': {
        char e = ps->p[1];
        if (!e) return perr(ps, "trailing backslash");
        ps->p += 2;
        cls_t c;
        memset(&c, 0, sizeof(c));
        if (shorthand(e, &c)) {
            int idx = add_class(ps, &c);
            if (idx < 0) return -1;
            n = new_node(ps, N_CLASS);
            if (n < 0) return -1;
            ps->nodes[n].cls = (uint16_t)idx;
            return n;
        }
        if (!is_meta(e)) return perr(ps, "unsupported escape \\%c", e);
        n = new_node(ps, N_CHAR);
        if (n < 0) return -1;
        ps->nodes[n].c = (uint8_t)e;
        return n;
    }
    case '*': case '+': case '?': case '{':
        return perr(ps, "quantifier without operand");
    case ')': case '|': case 0:
        return perr(ps, "unexpected end of expression");
    case ']': case '}':
        return perr(ps, "unescaped '%c'", ch);
    default:
        ps->p++;
        n = new_node(ps, N_CHAR);
        if (n < 0) return -1;
        ps->nodes[n].c = (uint8_t)ch;
        return n;
    }
}

static int parse_repeat(parser_t *ps)
{
    int atom = parse_atom(ps);
    if (atom < 0) return -1;
    for (;;) {
        int min, max;
        char q = *ps->p;
        if (q == '*') { min = 0; max = -1; ps->p++; }
        else if (q == '+') { min = 1; max = -1; ps->p++; }
        else if (q == '?') { min = 0; max = 1; ps->p++; }
        else if (q == '{') {
            ps->p++;
            if (parse_int(ps, &min) < 0) return -1;
            if (*ps->p == '}') {
                max = min;
            } else if (*ps->p == ',') {
                ps->p++;
                if (*ps->p == '}') max = -1;
                else if (parse_int(ps, &max) < 0) return -1;
            } else {
                return perr(ps, "bad {} quantifier");
            }
            if (*ps->p != '}') return perr(ps, "missing }");
            ps->p++;
            if (max != -1 && max < min) return perr(ps, "{n,m} with m < n");
        } else {
            break;
        }
        if (*ps->p == '?') return perr(ps, "lazy quantifiers are not supported");
        if (ps->nodes[atom].type == N_BOL || ps->nodes[atom].type == N_EOL)
            return perr(ps, "quantifier on anchor");
        int n = new_node(ps, N_REP);
        if (n < 0) return -1;
        ps->nodes[n].a = atom;
        ps->nodes[n].min = (int16_t)min;
        ps->nodes[n].max = (int16_t)max;
        atom = n;
    }
    return atom;
}

/* A character parse_atom() would take as a plain literal. */
static int is_plain(char c)
{
    return c && !strchr("()[].^$\\*+?{}|", c);
}

static int is_quant(char c)
{
    return c && strchr("*+?{", c);
}

static int parse_cat(parser_t *ps)
{
    int left = -1;
    while (*ps->p && *ps->p != '|' && *ps->p != ')') {
        int r;
        if (is_plain(ps->p[0]) && !is_quant(ps->p[1])) {
            /* A run of unquantified literals is one node: policy patterns are
             * mostly long hex literals, and a node per character (plus a CAT
             * per character) needs too much heap on the device. */
            const char *s = ps->p;
            while (is_plain(ps->p[0]) && !is_quant(ps->p[1])) ps->p++;
            if ((r = new_node(ps, N_STR)) < 0) return -1;
            ps->nodes[r].a = (int)(s - ps->start);
            ps->nodes[r].b = (int)(ps->p - s);
        } else if ((r = parse_repeat(ps)) < 0) {
            return -1;
        }
        if (left < 0) {
            left = r;
        } else {
            int n = new_node(ps, N_CAT);
            if (n < 0) return -1;
            ps->nodes[n].a = left;
            ps->nodes[n].b = r;
            left = n;
        }
    }
    if (left < 0) return new_node(ps, N_EMPTY);
    return left;
}

static int parse_alt(parser_t *ps)
{
    int left = parse_cat(ps);
    if (left < 0) return -1;
    while (*ps->p == '|') {
        ps->p++;
        int right = parse_cat(ps);
        if (right < 0) return -1;
        int n = new_node(ps, N_ALT);
        if (n < 0) return -1;
        ps->nodes[n].a = left;
        ps->nodes[n].b = right;
        left = n;
    }
    return left;
}

/* ------------------------------------------------------------ codegen --- */

enum { I_CHAR, I_ANY, I_CLASS, I_SPLIT, I_JMP, I_MATCH, I_BOL, I_EOL };

typedef struct {
    uint8_t op;
    uint8_t c;
    uint16_t cls;
    uint16_t x, y;
} inst_t;

struct regex_prog {
    inst_t *insts;
    int n;
    cls_t *classes;
    int n_classes;
};

typedef struct {
    parser_t *ps;
    inst_t *insts;
    int n, cap;
} gen_t;

static int emit(gen_t *g, uint8_t op)
{
    if (g->n >= REGEX_MAX_INSTS) return perr(g->ps, "pattern compiles to more than %d instructions", REGEX_MAX_INSTS);
    if (g->n == g->cap) {
        int nc = g->cap ? g->cap * 2 : 64;
        inst_t *ni = realloc(g->insts, (size_t)nc * sizeof(inst_t));
        if (!ni) return perr(g->ps, "out of memory");
        g->insts = ni;
        g->cap = nc;
    }
    memset(&g->insts[g->n], 0, sizeof(inst_t));
    g->insts[g->n].op = op;
    return g->n++;
}

/* Exact number of instructions gen() emits for node ni (saturates past the
 * limit), so the program is allocated once instead of grown by doubling. */
static long count_insts(const parser_t *ps, int ni)
{
    const long cap = REGEX_MAX_INSTS + 1;
    const node_t *nd = &ps->nodes[ni];
    long n;
    switch (nd->type) {
    case N_EMPTY:
        return 0;
    case N_STR:
        return nd->b;
    case N_CAT:
    case N_ALT: {
        long k = 0;
        int i = ni;
        n = 0;
        for (; ps->nodes[i].type == nd->type && n < cap; i = ps->nodes[i].a, k++)
            n += count_insts(ps, ps->nodes[i].b);
        n += count_insts(ps, i);
        if (nd->type == N_ALT) n += 2 * k; /* SPLIT + JMP per alternative but the last */
        break;
    }
    case N_REP: {
        long c = count_insts(ps, nd->a);
        n = nd->min * c + (nd->max == -1 ? c + 2 : (long)(nd->max - nd->min) * (c + 1));
        break;
    }
    default:
        return 1;
    }
    return n < cap ? n : cap;
}

static int gen(gen_t *g, int ni)
{
    const node_t *nd = &g->ps->nodes[ni];
    int pc, l1, j;
    switch (nd->type) {
    case N_EMPTY:
        return 0;
    case N_CHAR:
        if ((pc = emit(g, I_CHAR)) < 0) return -1;
        g->insts[pc].c = nd->c;
        return 0;
    case N_STR:
        for (int i = 0; i < nd->b; i++) {
            if ((pc = emit(g, I_CHAR)) < 0) return -1;
            g->insts[pc].c = (uint8_t)g->ps->start[nd->a + i];
        }
        return 0;
    case N_ANY:
        return emit(g, I_ANY) < 0 ? -1 : 0;
    case N_BOL:
        return emit(g, I_BOL) < 0 ? -1 : 0;
    case N_EOL:
        return emit(g, I_EOL) < 0 ? -1 : 0;
    case N_CLASS:
        if ((pc = emit(g, I_CLASS)) < 0) return -1;
        g->insts[pc].cls = nd->cls;
        return 0;
    case N_CAT:
    case N_ALT: {
        /* The parser builds left-deep trees; flatten the spine iteratively so
         * long literal patterns don't recurse thousands of frames deep. */
        int count = 1;
        for (int k = ni; g->ps->nodes[k].type == nd->type; k = g->ps->nodes[k].a) count++;
        int *items = malloc((size_t)count * sizeof(int));
        if (!items) return perr(g->ps, "out of memory");
        int k = ni, idx = count;
        while (g->ps->nodes[k].type == nd->type) {
            items[--idx] = g->ps->nodes[k].b;
            k = g->ps->nodes[k].a;
        }
        items[--idx] = k;
        int rc = 0;
        if (nd->type == N_CAT) {
            for (int i = 0; i < count && rc == 0; i++) rc = gen(g, items[i]);
        } else {
            /* split L1, next; L1: x1; jmp END; next: split L2, next2; ... xk; END: */
            int *jmps = malloc((size_t)count * sizeof(int));
            if (!jmps) {
                free(items);
                return perr(g->ps, "out of memory");
            }
            int nj = 0;
            for (int i = 0; i < count && rc == 0; i++) {
                if (i < count - 1) {
                    if ((l1 = emit(g, I_SPLIT)) < 0) { rc = -1; break; }
                    g->insts[l1].x = (uint16_t)g->n;
                    if ((rc = gen(g, items[i])) < 0) break;
                    if ((j = emit(g, I_JMP)) < 0) { rc = -1; break; }
                    jmps[nj++] = j;
                    g->insts[l1].y = (uint16_t)g->n;
                } else {
                    rc = gen(g, items[i]);
                }
            }
            for (int i = 0; i < nj; i++) g->insts[jmps[i]].x = (uint16_t)g->n;
            free(jmps);
        }
        free(items);
        return rc;
    }
    case N_REP: {
        for (int i = 0; i < nd->min; i++)
            if (gen(g, nd->a) < 0) return -1;
        if (nd->max == -1) {
            /* L1: split L2, L3; L2: child; jmp L1; L3: */
            if ((l1 = emit(g, I_SPLIT)) < 0) return -1;
            g->insts[l1].x = (uint16_t)g->n;
            if (gen(g, nd->a) < 0) return -1;
            if ((j = emit(g, I_JMP)) < 0) return -1;
            g->insts[j].x = (uint16_t)l1;
            g->insts[l1].y = (uint16_t)g->n;
            return 0;
        }
        int opt = nd->max - nd->min;
        int *splits = opt ? malloc((size_t)opt * sizeof(int)) : NULL;
        if (opt && !splits) return perr(g->ps, "out of memory");
        for (int i = 0; i < opt; i++) {
            if ((splits[i] = emit(g, I_SPLIT)) < 0) { free(splits); return -1; }
            g->insts[splits[i]].x = (uint16_t)g->n;
            if (gen(g, nd->a) < 0) { free(splits); return -1; }
        }
        for (int i = 0; i < opt; i++) g->insts[splits[i]].y = (uint16_t)g->n;
        free(splits);
        return 0;
    }
    }
    return perr(g->ps, "internal error");
}

int regex_compile(const char *pattern, regex_prog_t **out, char *err, size_t errlen)
{
    parser_t ps;
    memset(&ps, 0, sizeof(ps));
    ps.p = ps.start = pattern;
    ps.err = err;
    ps.errlen = errlen;
    *out = NULL;
    if (err && errlen) err[0] = 0;

    int root = parse_alt(&ps);
    if (root >= 0 && *ps.p) root = perr(&ps, "unbalanced )");

    gen_t g;
    memset(&g, 0, sizeof(g));
    g.ps = &ps;
    int rc = -1;
    if (root >= 0) {
        long want = count_insts(&ps, root) + 1; /* + I_MATCH */
        g.cap = (int)(want < REGEX_MAX_INSTS ? want : REGEX_MAX_INSTS);
        g.insts = malloc((size_t)g.cap * sizeof(inst_t));
        if (!g.insts) root = perr(&ps, "out of memory");
    }
    if (root >= 0 && gen(&g, root) == 0 && emit(&g, I_MATCH) >= 0) {
        regex_prog_t *p = calloc(1, sizeof(*p));
        if (p) {
            p->insts = g.insts;
            p->n = g.n;
            p->classes = ps.classes;
            p->n_classes = ps.n_classes;
            g.insts = NULL;
            ps.classes = NULL;
            *out = p;
            rc = 0;
        } else {
            perr(&ps, "out of memory");
        }
    }
    free(g.insts);
    free(ps.classes);
    free(ps.nodes);
    return rc;
}

/* ------------------------------------------------------------ Pike VM --- */

typedef struct {
    uint16_t *pcs;
    int n;
} tlist_t;

typedef struct {
    const regex_prog_t *p;
    uint32_t *mark;
    uint32_t gen;
    uint16_t *stack;
    size_t len;
} vm_t;

static void addthread(vm_t *vm, tlist_t *l, uint16_t pc0, size_t pos)
{
    int sp = 0;
    vm->stack[sp++] = pc0;
    while (sp) {
        uint16_t pc = vm->stack[--sp];
        if (vm->mark[pc] == vm->gen) continue;
        vm->mark[pc] = vm->gen;
        const inst_t *in = &vm->p->insts[pc];
        switch (in->op) {
        case I_JMP:
            vm->stack[sp++] = in->x;
            break;
        case I_SPLIT:
            vm->stack[sp++] = in->y;
            vm->stack[sp++] = in->x;
            break;
        case I_BOL:
            if (pos == 0) vm->stack[sp++] = (uint16_t)(pc + 1);
            break;
        case I_EOL:
            if (pos == vm->len) vm->stack[sp++] = (uint16_t)(pc + 1);
            break;
        default:
            l->pcs[l->n++] = pc;
            break;
        }
    }
}

size_t regex_ws_size(size_t n)
{
    /* mark[n] (uint32), two thread lists of n (uint16), and the addthread
     * stack: each pc is pushed at most once per generation but SPLIT pushes
     * two entries before marking, so 2n+2 bounds it. */
    return n * sizeof(uint32_t) + 2 * n * sizeof(uint16_t) + (2 * n + 2) * sizeof(uint16_t);
}

int regex_full_match(const regex_prog_t *p, const char *s, size_t len)
{
    void *ws = malloc(regex_ws_size((size_t)p->n));
    if (!ws) return REGEX_NOMEM;
    int r = regex_full_match_ws(p, s, len, ws);
    free(ws);
    return r;
}

int regex_full_match_ws(const regex_prog_t *p, const char *s, size_t len, void *ws)
{
    size_t n = (size_t)p->n;
    uint8_t *mem = ws;
    vm_t vm = {
        .p = p,
        .mark = (uint32_t *)mem,
        .gen = 0,
        .stack = (uint16_t *)(mem + n * sizeof(uint32_t) + 2 * n * sizeof(uint16_t)),
        .len = len,
    };
    memset(vm.mark, 0xff, n * sizeof(uint32_t));
    tlist_t a = {(uint16_t *)(mem + n * sizeof(uint32_t)), 0};
    tlist_t b = {(uint16_t *)(mem + n * sizeof(uint32_t) + n * sizeof(uint16_t)), 0};
    tlist_t *cl = &a, *nl = &b;
    uint32_t steps = 0;
    int result = 0;

    vm.gen = 1;
    addthread(&vm, cl, 0, 0);
    for (size_t pos = 0; pos < len; pos++) {
        if (cl->n == 0) goto done;
        vm.gen++;
        nl->n = 0;
        uint8_t ch = (uint8_t)s[pos];
        for (int i = 0; i < cl->n; i++) {
            if (++steps > REGEX_STEP_BUDGET) {
                result = REGEX_BUDGET;
                goto done;
            }
            const inst_t *in = &p->insts[cl->pcs[i]];
            int ok = 0;
            switch (in->op) {
            case I_CHAR: ok = (ch == in->c); break;
            case I_ANY: ok = 1; break;
            case I_CLASS: ok = (p->classes[in->cls].bits[ch >> 5] >> (ch & 31)) & 1; break;
            default: ok = 0; break; /* MATCH before end of input: ignored (full match) */
            }
            if (ok) addthread(&vm, nl, (uint16_t)(cl->pcs[i] + 1), pos + 1);
        }
        tlist_t *t = cl;
        cl = nl;
        nl = t;
    }
    for (int i = 0; i < cl->n; i++)
        if (p->insts[cl->pcs[i]].op == I_MATCH) {
            result = 1;
            break;
        }
done:
    return result;
}

size_t regex_prog_insts(const regex_prog_t *p)
{
    return p ? (size_t)p->n : 0;
}

void regex_free(regex_prog_t *p)
{
    if (!p) return;
    free(p->insts);
    free(p->classes);
    free(p);
}
