#ifndef WPACRACK_MASK_H
#define WPACRACK_MASK_H

#include <stdint.h>

#define MASK_MAX_POS 32
#define MASK_CHARSET_LEN 256

typedef struct {
    char  mask[256];                 /* original mask text            */
    int   npos;                      /* number of positions           */
    char *cs[MASK_MAX_POS];          /* charset per position          */
    int   cslen[MASK_MAX_POS];       /* charset length per position   */
    uint64_t keyspace;               /* total candidates              */

    int   incremental;               /* try lengths minlen..maxlen    */
    int   minlen, maxlen;
    char *incs;                      /* incremental charset           */
    int   incslen;

    char  custom[4][MASK_CHARSET_LEN]; /* storage for ?1-?4           */
    char  builtin[MASK_MAX_POS][MASK_CHARSET_LEN]; /* builtin storage */
} mask_t;

/* Parse a mask like "?d?d?d?d?d?d?d?d". `custom` may be NULL (defaults to
 * ?l?u?d?s). Returns 0 on success, -1 on error. */
int mask_parse(mask_t *m, const char *mask,
               const char *c1, const char *c2,
               const char *c3, const char *c4,
               int inc_min, int inc_max);

/* Expand candidate at index `idx` into `out` (NUL-terminated). */
void mask_candidate(const mask_t *m, uint64_t idx, char *out);

/* Incremental keyspace: sum over lengths of incslen^len. */
uint64_t mask_incremental_keyspace(const mask_t *m);

#endif
