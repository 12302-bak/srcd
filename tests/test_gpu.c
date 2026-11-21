/* Verifies the CUDA device crypto by compiling cu/gpu_cuda.cu as portable C
 * (-DWPACRACK_CUDA_EMULATE) and exercising the exact functions the GPU kernel
 * runs, against an independent RFC 6070 vector and a synthetic WPA handshake.
 *
 * This proves the device algorithm (PBKDF2 -> PMK -> PTK -> MIC/PMKID) is
 * correct without any NVIDIA hardware; only the CUDA runtime glue is untested.
 */
#include "../src/crypto.h"
#include "../src/pcap.h"

#include <stdio.h>
#include <string.h>

/* Provided by cu/gpu_cuda.cu in host-emulation mode. */
int gpu_emul_pbkdf2(const uint8_t *pass, uint32_t passlen,
                    const uint8_t *salt, uint32_t saltlen,
                    uint32_t iters, uint8_t *dk, uint32_t dklen);
int gpu_emul_try_pmk(const uint8_t pmk[32], const wpa_capture *cap);

static int fail = 0;
static void expect(const char *what, int got, int exp) {
    if (got != exp) { printf("FAIL %s: got %d exp %d\n", what, got, exp); fail++; }
    else printf("ok   %s\n", what);
}

/* Build an EAPOL-Key frame (descriptor 2) with `nonce`/`keyinfo` and a valid
 * MIC under `kck`. Returns the frame length; the MIC field is left zeroed and
 * the MIC is returned in `mic` (the convention pcap.c stores for wpa_try_pmk). */
static size_t build_eapol(uint8_t *out, const uint8_t nonce[32],
                          uint16_t keyinfo, const uint8_t kck[16],
                          uint8_t mic[16]) {
    uint8_t body[192];
    size_t p = 0;
    body[p++] = 0x02;                                  /* RSN/WPA2 descriptor */
    body[p++] = (uint8_t)(keyinfo >> 8); body[p++] = (uint8_t)keyinfo;
    body[p++] = 0x00; body[p++] = 0x10;                /* key length */
    memset(body + p, 0, 8); p += 8;                    /* replay counter */
    memcpy(body + p, nonce, 32); p += 32;              /* nonce */
    memset(body + p, 0, 16); p += 16;                  /* key IV */
    memset(body + p, 0, 8);  p += 8;                   /* key RSC */
    memset(body + p, 0, 8);  p += 8;                   /* key ID */
    memset(body + p, 0, 16); p += 16;                  /* key MIC (zeroed) */
    body[p++] = 0x00; body[p++] = 0x00;                /* key data length */

    out[0] = 0x01; out[1] = 0x03;                      /* EAPOL version, type Key */
    out[2] = (uint8_t)(p >> 8); out[3] = (uint8_t)p;
    memcpy(out + 4, body, p);
    size_t len = 4 + p;
    wpa_eapol_mic(kck, out, len, mic);                 /* MIC over zeroed frame */
    return len;
}

int main(int argc, char **argv) {
    /* 1) RFC 6070 test case 2: P="password", S="salt", c=4096, dkLen=20. */
    {
        static const uint8_t exp[20] = {
            0x4b,0x00,0x79,0x01,0xb7,0x65,0x48,0x9a,0xbe,0xad,
            0x49,0xd9,0x26,0xf7,0x21,0xd0,0x65,0xa4,0x29,0xc1
        };
        uint8_t dk[20];
        gpu_emul_pbkdf2((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4,
                        4096, dk, 20);
        if (memcmp(dk, exp, 20) == 0) printf("ok   rfc6070-4096-20\n");
        else { printf("FAIL rfc6070-4096-20: "); for (int i = 0; i < 20; i++) printf("%02x", dk[i]); printf("\n"); fail++; }
    }

    /* 2) Device PBKDF2 agrees with the verified host PBKDF2 (32-byte PMK). */
    {
        uint8_t dk_dev[32], dk_host[32];
        gpu_emul_pbkdf2((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, dk_dev, 32);
        pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, dk_host, 32);
        expect("dev==host pbkdf2(password,salt,4096,32)", memcmp(dk_dev, dk_host, 32) == 0, 1);

        gpu_emul_pbkdf2((const uint8_t *)"1234", 4, (const uint8_t *)"test", 4, 4096, dk_dev, 32);
        pbkdf2_sha1((const uint8_t *)"1234", 4, (const uint8_t *)"test", 4, 4096, dk_host, 32);
        expect("dev==host pbkdf2(1234,test,4096,32)", memcmp(dk_dev, dk_host, 32) == 0, 1);
    }

    /* 3) Full device path on a synthetic handshake: PMK -> PTK -> MIC. */
    {
        static const uint8_t aa[6]    = {0x00,0x11,0x22,0x33,0x44,0x55};
        static const uint8_t spa[6]   = {0x66,0x77,0x88,0x99,0xaa,0xbb};
        static const uint8_t anonce[32] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8};
        static const uint8_t snonce[32] = {0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};
        const uint8_t *ssid = (const uint8_t *)"test";
        const char *pass = "1234";

        uint8_t pmk[32], ptk[48], mic[16], eapol[192];
        wpa_pmk((const uint8_t *)pass, 4, ssid, 4, pmk);
        wpa_ptk(pmk, aa, spa, anonce, snonce, ptk);

        wpa_capture cap;
        memset(&cap, 0, sizeof(cap));
        cap.ssid_len = 4;
        memcpy(cap.ssid, ssid, 4);
        memcpy(cap.aa, aa, 6);
        memcpy(cap.spa, spa, 6);
        memcpy(cap.anonce, anonce, 32);
        memcpy(cap.snonce, snonce, 32);
        cap.have_eapol = 1;
        cap.eapol_len = build_eapol(eapol, snonce, 0x010a, ptk, mic); /* msg 2 */
        memcpy(cap.eapol, eapol, cap.eapol_len);
        memcpy(cap.key_mic, mic, 16);

        /* Device verify: correct PMK matches, wrong PMK does not. */
        expect("device try_pmk(pmk 1234) == 1", gpu_emul_try_pmk(pmk, &cap), 1);
        uint8_t bad[32] = {0};
        expect("device try_pmk(bad) == 0",    gpu_emul_try_pmk(bad, &cap), 0);
    }

    /* 4) Cross-check on the real aircrack capture if it is available. */
    if (argc > 1) {
        wpa_capture cap;
        if (wpa_capture_from_pcap(argv[1], &cap) == 0 && cap.have_eapol) {
            uint8_t pmk[32];
            wpa_pmk((const uint8_t *)"Induction", 9, cap.ssid, cap.ssid_len, pmk);
            expect("device try_pmk(Induction) on real capture", gpu_emul_try_pmk(pmk, &cap), 1);
        } else {
            printf("skip: real capture '%s' unusable\n", argv[1]);
        }
    }

    printf(fail ? "\n%d FAILURE(S)\n" : "\nall pass\n", fail);
    return fail ? 1 : 0;
}
