#include "crypto.h"
#include "sha1.h"

#include <string.h>

void hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg,
               size_t msglen, uint8_t out[20]) {
    uint8_t kblock[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[20];
    sha1_ctx c;
    size_t i;

    memset(kblock, 0, sizeof(kblock));
    if (keylen > 64) {
        sha1(key, keylen, kblock);
        keylen = 20;
    } else {
        memcpy(kblock, key, keylen);
    }

    for (i = 0; i < 64; i++) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5C;
    }

    sha1_init(&c);
    sha1_update(&c, ipad, 64);
    sha1_update(&c, msg, msglen);
    sha1_final(&c, inner);

    sha1_init(&c);
    sha1_update(&c, opad, 64);
    sha1_update(&c, inner, 20);
    sha1_final(&c, out);
}

void pbkdf2_sha1(const uint8_t *pass, size_t passlen, const uint8_t *salt,
                 size_t saltlen, uint32_t iters, uint8_t *dk, size_t dklen) {
    /* Precompute the passphrase HMAC pads so each of the 2*iters HMACs per
     * block only re-hashes the changing message, not the fixed key block. */
    uint8_t kblock[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    sha1_ctx ic, oc;
    uint8_t u[20], t[20], inner[20], block[4];
    uint32_t block_index = 1;
    size_t produced = 0;
    size_t i;
    uint32_t iter;

    memset(kblock, 0, sizeof(kblock));
    if (passlen > 64) {
        sha1(pass, passlen, kblock);
        passlen = 20;
    } else {
        memcpy(kblock, pass, passlen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5C;
    }
    sha1_init(&ic); sha1_update(&ic, ipad, 64); /* state after ipad block */
    sha1_init(&oc); sha1_update(&oc, opad, 64); /* state after opad block */

    while (produced < dklen) {
        size_t take = dklen - produced;
        sha1_ctx c, d;

        /* U1 = HMAC(P, S || INT_32_BE(block_index)) */
        block[0] = (uint8_t)(block_index >> 24);
        block[1] = (uint8_t)(block_index >> 16);
        block[2] = (uint8_t)(block_index >> 8);
        block[3] = (uint8_t)(block_index);
        c = ic;
        sha1_update(&c, salt, saltlen);
        sha1_update(&c, block, 4);
        sha1_final(&c, inner);
        d = oc;
        sha1_update(&d, inner, 20);
        sha1_final(&d, u);

        memcpy(t, u, 20);

        for (iter = 1; iter < iters; iter++) {
            c = ic;
            sha1_update(&c, u, 20);
            sha1_final(&c, inner);
            d = oc;
            sha1_update(&d, inner, 20);
            sha1_final(&d, u);
            for (i = 0; i < 20; i++) t[i] ^= u[i];
        }

        if (take > 20) take = 20;
        memcpy(dk + produced, t, take);
        produced += take;
        block_index++;
    }
}

void wpa_prf(const uint8_t *key, size_t keylen, const uint8_t *label,
             size_t labellen, const uint8_t *data, size_t datalen,
             uint8_t *out, size_t outlen) {
    /* IEEE 802.11i 8.5.1.1, as implemented by wpa_supplicant sha1_prf():
     *   HMAC-SHA1(K, label || 0x00 || data || counter)
     * where `label` INCLUDES its trailing NUL (the 0x00 separator) and
     * `counter` is one byte starting at 0, incremented per 160-bit block. */
    uint8_t msg[64 + 256];
    size_t produced = 0;
    uint8_t counter = 0;

    while (produced < outlen) {
        size_t take = outlen - produced;
        uint8_t h[20];
        uint8_t *p = msg;

        memcpy(p, label, labellen); p += labellen;
        memcpy(p, data, datalen); p += datalen;
        *p++ = counter;

        hmac_sha1(key, keylen, msg, (size_t)(p - msg), h);
        if (take > 20) take = 20;
        memcpy(out + produced, h, take);
        produced += take;
        counter++;
    }
}

void wpa_pmk(const uint8_t *pass, size_t passlen, const uint8_t *ssid,
             size_t ssidlen, uint8_t pmk[32]) {
    pbkdf2_sha1(pass, passlen, ssid, ssidlen, 4096, pmk, 32);
}

static void sort_copy(uint8_t *dst, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) <= 0) {
        memcpy(dst, a, n);
        memcpy(dst + n, b, n);
    } else {
        memcpy(dst, b, n);
        memcpy(dst + n, a, n);
    }
}

void wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
             const uint8_t anonce[32], const uint8_t snonce[32],
             uint8_t ptk[48]) {
    static const uint8_t label[] = "Pairwise key expansion";
    uint8_t data[12 + 64];
    uint8_t aabb[12];
    uint8_t nn[64];

    sort_copy(aabb, aa, spa, 6);
    sort_copy(nn, anonce, snonce, 32);
    memcpy(data, aabb, 12);
    memcpy(data + 12, nn, 64);

    wpa_prf(pmk, 32, label, sizeof(label), data, sizeof(data), ptk, 48);
}

void wpa_eapol_mic(const uint8_t kck[16], const uint8_t *eapol,
                   size_t eapol_len, uint8_t mic[16]) {
    uint8_t h[20];
    hmac_sha1(kck, 16, eapol, eapol_len, h);
    memcpy(mic, h, 16);
}

void wpa_pmkid(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
               uint8_t pmkid[16]) {
    static const uint8_t label[] = "PMK Name";
    uint8_t msg[9 + 12];
    uint8_t h[20];

    memcpy(msg, label, sizeof(label) - 1);
    memcpy(msg + 8, aa, 6);
    memcpy(msg + 14, spa, 6);

    hmac_sha1(pmk, 32, msg, 8 + 12, h);
    memcpy(pmkid, h, 16);
}
