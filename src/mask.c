#include "mask.h"

#include <stdio.h>
#include <string.h>

static const char *BUILTIN(char c) {
    switch (c) {
    case 'd': return "0123456789";
    case 'l': return "abcdefghijklmnopqrstuvwxyz";
    case 'u': return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    case 's': return " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    case 'a': return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    case 'h': return "0123456789abcdef";
    case 'H': return "0123456789ABCDEF";
    case 'b': return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; /* fallback */
    default:  return NULL;
    }
}

static const char *builtin(const char *name) {
    /* Returns a static string for a builtin token, or NULL. */
    if (strlen(name) == 1) return BUILTIN(name[0]);
    if (strcmp(name, "?d") == 0) return "0123456789";
    if (strcmp(name, "?l") == 0) return "abcdefghijklmnopqrstuvwxyz";
    if (strcmp(name, "?u") == 0) return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return NULL;
}

static int resolve(mask_t *m, int pos, const char *tok,
                   const char *c[4], const char *cname[4]) {
    /* tok points at a "?x" token. */
    char ch = tok[1];
    const char *set = NULL;
    if (ch >= '1' && ch <= '4') {
        int ci = ch - '1';
        if (c[ci]) set = c[ci];
        else if (cname[ci]) set = cname[ci];
        else return -1;
    } else if (ch == 'b') {
        set = m->custom[0]; /* handled below for full byte range */
    } else {
        set = BUILTIN(ch);
    }
    if (!set) return -1;

    if (ch == 'b') {
        /* ?b: full 0x00..0xFF; store inline in builtin[pos] */
        int i;
        for (i = 0; i < 256; i++) m->builtin[pos][i] = (char)i;
        m->cs[pos] = m->builtin[pos];
        m->cslen[pos] = 256;
        return 0;
    }

    m->cs[pos] = (char *)set;
    m->cslen[pos] = (int)strlen(set);
    return 0;
}

static uint64_t pow_u64(uint64_t base, int exp) {
    uint64_t r = 1;
    while (exp-- > 0) {
        if (r > UINT64_MAX / base) return UINT64_MAX;
        r *= base;
    }
    return r;
}

int mask_parse(mask_t *m, const char *mask,
               const char *c1, const char *c2,
               const char *c3, const char *c4,
               int inc_min, int inc_max) {
    const char *c[4] = { c1, c2, c3, c4 };
    const char *cname[4] = { "?l?u?d?s", NULL, NULL, NULL };
    size_t len = strlen(mask);
    int pos = 0;
    int i;

    memset(m, 0, sizeof(*m));
    if (len >= sizeof(m->mask)) return -1;
    strcpy(m->mask, mask);

    /* Save custom charsets. */
    for (i = 0; i < 4; i++) {
        const char *src = c[i] ? c[i] : (i == 0 ? "?l?u?d?s" : NULL);
        if (src) {
            /* Expand if it's a composed token like ?l?u?d?s */
            if (strchr(src, '?') && strlen(src) > 1) {
                int outlen = 0;
                const char *p = src;
                while (*p) {
                    if (p[0] == '?' && p[1]) {
                        const char *s = builtin(p);
                        if (s) {
                            size_t sl = strlen(s);
                            if (outlen + (int)sl < MASK_CHARSET_LEN) {
                                memcpy(m->custom[i] + outlen, s, sl);
                                outlen += (int)sl;
                            }
                        }
                        p += 2;
                    } else {
                        if (outlen < MASK_CHARSET_LEN - 1)
                            m->custom[i][outlen++] = *p;
                        p++;
                    }
                }
                m->custom[i][outlen] = 0;
            } else {
                snprintf(m->custom[i], MASK_CHARSET_LEN, "%s", src);
            }
        }
    }

    /* Incremental mode: mask is a single charset token, e.g. "?d". */
    if (inc_min > 0 || inc_max > 0) {
        if (len != 2 || mask[0] != '?') return -1;
        const char *set = NULL;
        char ch = mask[1];
        if (ch >= '1' && ch <= '4') {
            int ci = ch - '1';
            set = m->custom[ci];
        } else if (ch == 'b') {
            set = m->builtin[0];
            int k;
            for (k = 0; k < 256; k++) m->builtin[0][k] = (char)k;
        } else {
            set = BUILTIN(ch);
        }
        if (!set) return -1;
        m->incremental = 1;
        m->incs = (char *)set;
        m->incslen = (int)strlen(set);
        m->minlen = inc_min > 0 ? inc_min : 1;
        m->maxlen = inc_max > 0 ? inc_max : m->minlen;
        m->keyspace = mask_incremental_keyspace(m);
        return 0;
    }

    /* Positional mask: scan tokens. */
    for (i = 0; i < (int)len && pos < MASK_MAX_POS;) {
        if (mask[i] == '?' && mask[i + 1]) {
            if (resolve(m, pos, mask + i, c, cname) != 0) return -1;
            i += 2;
        } else {
            m->cs[pos] = (char *)&m->mask[i];
            m->cslen[pos] = 1;
            i += 1;
        }
        pos++;
    }
    m->npos = pos;

    m->keyspace = 1;
    for (i = 0; i < m->npos; i++) {
        if (m->keyspace > UINT64_MAX / (uint64_t)m->cslen[i]) {
            m->keyspace = UINT64_MAX;
            break;
        }
        m->keyspace *= (uint64_t)m->cslen[i];
    }
    return 0;
}

uint64_t mask_incremental_keyspace(const mask_t *m) {
    uint64_t total = 0;
    int l;
    for (l = m->minlen; l <= m->maxlen; l++) {
        uint64_t p = pow_u64((uint64_t)m->incslen, l);
        if (total > UINT64_MAX - p) return UINT64_MAX;
        total += p;
    }
    return total;
}

void mask_candidate(const mask_t *m, uint64_t idx, char *out) {
    if (m->incremental) {
        int l;
        for (l = m->minlen; l <= m->maxlen; l++) {
            uint64_t p = pow_u64((uint64_t)m->incslen, l);
            if (idx < p) {
                int k;
                for (k = l - 1; k >= 0; k--) {
                    out[k] = m->incs[idx % (uint64_t)m->incslen];
                    idx /= (uint64_t)m->incslen;
                }
                out[l] = 0;
                return;
            }
            idx -= p;
        }
        out[0] = 0;
        return;
    }
    {
        int k;
        for (k = m->npos - 1; k >= 0; k--) {
            out[k] = m->cs[k][idx % (uint64_t)m->cslen[k]];
            idx /= (uint64_t)m->cslen[k];
        }
        out[m->npos] = 0;
    }
}
