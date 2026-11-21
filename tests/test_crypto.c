#include "../src/crypto.h"
#include "../src/sha1.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void hex(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2] = d[b[i] >> 4];
        out[i * 2 + 1] = d[b[i] & 0xf];
    }
    out[n * 2] = 0;
}

static void check(const char *name, const uint8_t *got, const char *exphex) {
    char buf[256];
    hex(got, strlen(exphex) / 2, buf);
    if (strcmp(buf, exphex) != 0) {
        printf("FAIL %s\n  got %s\n  exp %s\n", name, buf, exphex);
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

int main(void) {
    uint8_t out[64];
    char hexbuf[256];

    /* RFC 3174: SHA1("abc") */
    sha1((const uint8_t *)"abc", 3, out);
    check("sha1 abc", out, "a9993e364706816aba3e25717850c26c9cd0d89d");

    /* RFC 2202 test case 2: HMAC-SHA1 */
    {
        uint8_t key[20];
        memset(key, 0x0b, 20);
        hmac_sha1(key, 20, (const uint8_t *)"Hi There", 8, out);
        check("hmac rfc2202-2", out, "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    /* RFC 6070: PBKDF2-HMAC-SHA1 */
    pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4,
                1, out, 20);
    check("pbkdf2 i=1", out, "0c60c80f961f0e71f3a9b524af6012062fe037a6");

    pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4,
                4096, out, 20);
    check("pbkdf2 i=4096", out, "4b007901b765489abead49d926f721d065a429c1");

    {
        static const uint8_t p[] = "passwordPASSWORDpassword";
        static const uint8_t s[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
        pbkdf2_sha1(p, sizeof(p) - 1, s, sizeof(s) - 1, 4096, out, 40);
        check("pbkdf2 40-byte", out,
              "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    }

    /* IEEE 802.11i PMK derivation is PBKDF2 with SSID as salt, 4096 iters. */
    {
        uint8_t pmk[32];
        wpa_pmk((const uint8_t *)"password", 8, (const uint8_t *)"IEEE", 4, pmk);
        /* Known value computed independently (not from hc)skeleton: */
        pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"IEEE", 4,
                    4096, out, 32);
        if (memcmp(pmk, out, 32) != 0) {
            printf("FAIL wpa_pmk consistency\n");
            failures++;
        } else {
            printf("ok   wpa_pmk consistency\n");
        }
        hex(pmk, 32, hexbuf);
        printf("     pmk(\"password\",\"IEEE\") = %s\n", hexbuf);
    }

    printf(failures ? "\n%d FAILURE(S)\n" : "\nall pass\n", failures);
    return failures ? 1 : 0;
}
