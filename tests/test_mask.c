#include "../src/mask.h"

#include <stdio.h>
#include <string.h>

static int fail = 0;
static void expect(const char *what, uint64_t got, uint64_t exp) {
    if (got != exp) { printf("FAIL %s: got %llu exp %llu\n", what, (unsigned long long)got, (unsigned long long)exp); fail++; }
    else printf("ok   %s (%llu)\n", what, (unsigned long long)got);
}

int main(void) {
    mask_t m;

    /* 8-digit numeric */
    if (mask_parse(&m, "?d?d?d?d?d?d?d?d", NULL, NULL, NULL, NULL, 0, 0) == 0) {
        expect("8d keyspace", m.keyspace, 100000000ULL);
        char buf[64];
        mask_candidate(&m, 0, buf);      expect("8d idx0", (uint64_t)strcmp(buf, "00000000"), 0);
        mask_candidate(&m, 12345678, buf); expect("8d idx12345678", (uint64_t)strcmp(buf, "12345678"), 0);
        mask_candidate(&m, 99999999, buf); expect("8d idxmax", (uint64_t)strcmp(buf, "99999999"), 0);
    } else { printf("FAIL parse 8d\n"); fail++; }

    /* "?u?l?l?d" mixed */
    if (mask_parse(&m, "?u?l?l?d", NULL, NULL, NULL, NULL, 0, 0) == 0) {
        expect("ulld keyspace", m.keyspace, 26ULL * 26 * 26 * 10);
        char buf[64];
        mask_candidate(&m, 0, buf); expect("ulld idx0", (uint64_t)strcmp(buf, "Aaa0"), 0);
        mask_candidate(&m, 26 * 26 * 26 * 10 - 1, buf); expect("ulld idxmax", (uint64_t)strcmp(buf, "Zzz9"), 0);
    } else { printf("FAIL parse ulld\n"); fail++; }

    /* incremental digits 4..8 */
    if (mask_parse(&m, "?d", NULL, NULL, NULL, NULL, 4, 8) == 0) {
        uint64_t exp = 10000ULL + 100000 + 1000000 + 10000000 + 100000000;
        expect("inc 4..8 keyspace", m.keyspace, exp);
        char buf[64];
        mask_candidate(&m, 0, buf);      expect("inc idx0", (uint64_t)strcmp(buf, "0000"), 0);
        mask_candidate(&m, 9999, buf);   expect("inc idx9999", (uint64_t)strcmp(buf, "9999"), 0);
        mask_candidate(&m, 10000, buf);  expect("inc idx10000", (uint64_t)strcmp(buf, "00000"), 0);
    } else { printf("FAIL parse inc\n"); fail++; }

    /* custom charset ?1?1?1 with ?1=abc */
    if (mask_parse(&m, "?1?1?1", "abc", NULL, NULL, NULL, 0, 0) == 0) {
        expect("c1 keyspace", m.keyspace, 27);
        char buf[64];
        mask_candidate(&m, 0, buf); expect("c1 idx0", (uint64_t)strcmp(buf, "aaa"), 0);
        mask_candidate(&m, 26, buf); expect("c1 idx26", (uint64_t)strcmp(buf, "ccc"), 0);
    } else { printf("FAIL parse c1\n"); fail++; }

    printf(fail ? "\n%d FAILURE(S)\n" : "\nall pass\n", fail);
    return fail ? 1 : 0;
}
