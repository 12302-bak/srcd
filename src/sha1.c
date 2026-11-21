#include "sha1.h"

#include <string.h>

#define ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void sha1_compress(sha1_ctx *c, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, cc, d, e, f, k, tmp;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = c->h[0];
    b = c->h[1];
    cc = c->h[2];
    d = c->h[3];
    e = c->h[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & cc) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6;
        }
        tmp = ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = ROL(b, 30);
        b = a;
        a = tmp;
    }

    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

void sha1_init(sha1_ctx *c) {
    c->h[0] = 0x67452301;
    c->h[1] = 0xEFCDAB89;
    c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476;
    c->h[4] = 0xC3D2E1F0;
    c->nbytes = 0;
    c->buflen = 0;
}

void sha1_update(sha1_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    c->nbytes += len;
    while (len) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            sha1_compress(c, c->buf);
            c->buflen = 0;
        }
    }
}

void sha1_final(sha1_ctx *c, uint8_t out[20]) {
    uint64_t bitlen = c->nbytes * 8;
    uint8_t pad = 0x80;
    uint8_t zero = 0x00;
    uint8_t lenb[8];
    int i;

    sha1_update(c, &pad, 1);
    while (c->buflen != 56) sha1_update(c, &zero, 1);

    for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(bitlen >> (56 - i * 8));
    sha1_update(c, lenb, 8);

    for (i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, data, len);
    sha1_final(&c, out);
}
