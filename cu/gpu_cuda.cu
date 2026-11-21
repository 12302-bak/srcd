/* CUDA backend for srcd. Compiled with nvcc for real use, or as portable C
 * with -DWPACRACK_CUDA_EMULATE so the device crypto can be verified on a host
 * without an NVIDIA GPU (see tests/test_gpu.c).
 *
 * The device-side crypto mirrors the host implementation in src/crypto.c and
 * src/sha1.c (verified against RFC 6070/2202/3174 and a real WPA capture). In
 * emulation mode the same code is compiled with the CUDA keywords mapped to
 * plain C, so `test_gpu` proves the device algorithm is correct by comparing
 * it to RFC vectors and a real capture.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef WPACRACK_CUDA_EMULATE
/* Host emulation: CUDA keywords become plain C so the device functions compile
 * and run on the CPU. The kernel launch and host glue are excluded below. */
#define __device__
#define __global__
#define __constant__
#else
#include <cuda_runtime.h>
#endif

#include "../src/crack.h"

#define NPOS_MAX 32

struct wpa_hs_d {
    uint8_t ssid[32];
    uint32_t ssid_len;
    uint8_t aa[6], spa[6];
    uint8_t anonce[32], snonce[32];
    uint8_t eapol[192];
    uint32_t eapol_len;
    uint8_t key_mic[16];
    uint8_t pmkid[16];
    uint32_t have_pmkid;
    uint8_t pmkid_aa[6], pmkid_spa[6];
};

__constant__ struct wpa_hs_d g_hs;
__constant__ uint32_t g_npos;
__constant__ uint32_t g_cslen[NPOS_MAX];
__constant__ char g_cs[NPOS_MAX][256];

__device__ static uint32_t rol32(uint32_t v, uint32_t b) {
    return (v << b) | (v >> (32 - b));
}

__device__ static void sha1_block(uint32_t h[5], const uint8_t *block) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, tmp;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        tmp = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = tmp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/* Streaming SHA-1 over a message (single message per call). */
__device__ static void sha1_msg(const uint8_t *msg, uint32_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t buf[64];
    uint32_t pos = 0;
    while (len - pos >= 64) {
        sha1_block(h, msg + pos);
        pos += 64;
    }
    uint32_t rem = len - pos;
    for (uint32_t i = 0; i < rem; i++) buf[i] = msg[pos + i];
    buf[rem] = 0x80;
    uint32_t buflen = rem + 1;
    if (buflen > 56) {
        for (uint32_t i = buflen; i < 64; i++) buf[i] = 0;
        sha1_block(h, buf);
        buflen = 0;
    }
    for (uint32_t i = buflen; i < 56; i++) buf[i] = 0;
    uint64_t bitlen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) buf[56 + i] = (uint8_t)(bitlen >> (56 - i * 8));
    sha1_block(h, buf);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* SHA-1 continuing from a state that has already hashed a 64-byte prefix
 * block (ipad/opad). `total_len` is the total message length in bytes,
 * prefix block included, so the padding encodes the right bit length. */
__device__ static void sha1_pre(uint32_t h0[5], const uint8_t *msg, uint32_t len,
                                uint64_t total_len, uint8_t out[20]) {
    uint32_t h[5];
    uint8_t buf[64];
    uint32_t pos = 0;
    for (int i = 0; i < 5; i++) h[i] = h0[i];
    while (len - pos >= 64) { sha1_block(h, msg + pos); pos += 64; }
    uint32_t rem = len - pos;
    for (uint32_t i = 0; i < rem; i++) buf[i] = msg[pos + i];
    buf[rem] = 0x80;
    uint32_t buflen = rem + 1;
    if (buflen > 56) {
        for (uint32_t i = buflen; i < 64; i++) buf[i] = 0;
        sha1_block(h, buf);
        buflen = 0;
    }
    for (uint32_t i = buflen; i < 56; i++) buf[i] = 0;
    uint64_t bitlen = total_len * 8;
    for (int i = 0; i < 8; i++) buf[56 + i] = (uint8_t)(bitlen >> (56 - i * 8));
    sha1_block(h, buf);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

__device__ static void hmac_sha1(const uint8_t *key, uint32_t keylen,
                                 const uint8_t *msg, uint32_t msglen,
                                 uint8_t out[20]) {
    uint8_t kblock[64];
    uint8_t ipad[64], opad[64];
    uint8_t inner[20];
    uint32_t h[5];
    for (int i = 0; i < 64; i++) kblock[i] = 0;
    if (keylen > 64) {
        sha1_msg(key, keylen, kblock);
        keylen = 20;
    } else {
        for (uint32_t i = 0; i < keylen; i++) kblock[i] = key[i];
    }
    for (int i = 0; i < 64; i++) { ipad[i] = kblock[i] ^ 0x36; opad[i] = kblock[i] ^ 0x5C; }
    h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476; h[4] = 0xC3D2E1F0;
    sha1_block(h, ipad);
    sha1_pre(h, msg, msglen, 64 + (uint64_t)msglen, inner);
    h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476; h[4] = 0xC3D2E1F0;
    sha1_block(h, opad);
    sha1_pre(h, inner, 20, 64 + 20, out);
}

/* PBKDF2-HMAC-SHA1 with precomputed per-passphrase pads. */
__device__ static void pbkdf2_sha1(const uint8_t *pass, uint32_t passlen,
                                   const uint8_t *salt, uint32_t saltlen,
                                   uint32_t iters, uint8_t *dk, uint32_t dklen) {
    uint8_t kblock[64];
    uint8_t ipad[64], opad[64];
    uint8_t u[20], t[20], inner[20], m[32 + 4];
    uint32_t ih[5], oh[5];
    for (int i = 0; i < 64; i++) kblock[i] = 0;
    if (passlen > 64) { sha1_msg(pass, passlen, kblock); passlen = 20; }
    else for (uint32_t i = 0; i < passlen; i++) kblock[i] = pass[i];
    for (int i = 0; i < 64; i++) { ipad[i] = kblock[i] ^ 0x36; opad[i] = kblock[i] ^ 0x5C; }
    /* State after the fixed ipad/opad block, so each round's HMAC only hashes
     * the changing message (mirrors the verified host pbkdf2_sha1). */
    ih[0] = 0x67452301; ih[1] = 0xEFCDAB89; ih[2] = 0x98BADCFE; ih[3] = 0x10325476; ih[4] = 0xC3D2E1F0;
    sha1_block(ih, ipad);
    oh[0] = 0x67452301; oh[1] = 0xEFCDAB89; oh[2] = 0x98BADCFE; oh[3] = 0x10325476; oh[4] = 0xC3D2E1F0;
    sha1_block(oh, opad);

    uint32_t produced = 0;
    uint32_t block_index = 1;
    while (produced < dklen) {
        uint32_t take = dklen - produced;
        uint32_t n = 0;
        for (uint32_t i = 0; i < saltlen; i++) m[n++] = salt[i];
        m[n++] = (uint8_t)(block_index >> 24);
        m[n++] = (uint8_t)(block_index >> 16);
        m[n++] = (uint8_t)(block_index >> 8);
        m[n++] = (uint8_t)(block_index);
        sha1_pre(ih, m, n, 64 + (uint64_t)n, inner);   /* HMAC(P, salt||block) inner hash  */
        sha1_pre(oh, inner, 20, 64 + 20, u);           /* U1                                */
        for (int i = 0; i < 20; i++) t[i] = u[i];
        for (uint32_t iter = 1; iter < iters; iter++) {
            sha1_pre(ih, u, 20, 64 + 20, inner);
            sha1_pre(oh, inner, 20, 64 + 20, u);
            for (int i = 0; i < 20; i++) t[i] ^= u[i];
        }
        if (take > 20) take = 20;
        for (uint32_t i = 0; i < take; i++) dk[produced + i] = t[i];
        produced += take;
        block_index++;
    }
}

__device__ static void wpa_prf(const uint8_t *key, uint32_t keylen,
                               const uint8_t *label, uint32_t labellen,
                               const uint8_t *data, uint32_t datalen,
                               uint8_t *out, uint32_t outlen) {
    uint8_t msg[32 + 256];
    uint32_t produced = 0;
    uint8_t counter = 0;
    while (produced < outlen) {
        uint32_t take = outlen - produced;
        uint8_t h[20];
        uint32_t n = 0;
        for (uint32_t i = 0; i < labellen; i++) msg[n++] = label[i];
        for (uint32_t i = 0; i < datalen; i++) msg[n++] = data[i];
        msg[n++] = counter;
        hmac_sha1(key, keylen, msg, n, h);
        if (take > 20) take = 20;
        for (uint32_t i = 0; i < take; i++) out[produced + i] = h[i];
        produced += take;
        counter++;
    }
}

__device__ static void wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6],
                               const uint8_t spa[6], const uint8_t anonce[32],
                               const uint8_t snonce[32], uint8_t ptk[48]) {
    static const uint8_t label[] = "Pairwise key expansion"; /* 23 bytes w/ NUL */
    uint8_t data[12 + 64];
    /* min(AA,SPA)||max(AA,SPA) */
    int aacmp = 0;
    for (int i = 0; i < 6; i++) {
        if (aa[i] != spa[i]) { aacmp = aa[i] < spa[i] ? -1 : 1; break; }
    }
    if (aacmp <= 0) { for (int i = 0; i < 6; i++) { data[i] = aa[i]; data[i + 6] = spa[i]; } }
    else            { for (int i = 0; i < 6; i++) { data[i] = spa[i]; data[i + 6] = aa[i]; } }
    /* min(ANonce,SNonce)||max(ANonce,SNonce) */
    int ncmp = 0;
    for (int i = 0; i < 32; i++) {
        if (anonce[i] != snonce[i]) { ncmp = anonce[i] < snonce[i] ? -1 : 1; break; }
    }
    if (ncmp <= 0) { for (int i = 0; i < 32; i++) { data[12 + i] = anonce[i]; data[12 + 32 + i] = snonce[i]; } }
    else           { for (int i = 0; i < 32; i++) { data[12 + i] = snonce[i]; data[12 + 32 + i] = anonce[i]; } }
    wpa_prf(pmk, 32, label, sizeof(label), data, sizeof(data), ptk, 48);
}

__device__ static void wpa_eapol_mic(const uint8_t kck[16], const uint8_t *eapol,
                                     uint32_t eapol_len, uint8_t mic[16]) {
    uint8_t h[20];
    hmac_sha1(kck, 16, eapol, eapol_len, h);
    for (int i = 0; i < 16; i++) mic[i] = h[i];
}

__device__ static void wpa_pmkid(const uint8_t pmk[32], const uint8_t aa[6],
                                 const uint8_t spa[6], uint8_t pmkid[16]) {
    static const uint8_t label[] = "PMK Name";
    uint8_t msg[8 + 12];
    uint8_t h[20];
    for (int i = 0; i < 8; i++) msg[i] = label[i];
    for (int i = 0; i < 6; i++) { msg[8 + i] = aa[i]; msg[14 + i] = spa[i]; }
    hmac_sha1(pmk, 32, msg, 20, h);
    for (int i = 0; i < 16; i++) pmkid[i] = h[i];
}

/* Verify one PMK against the handshake. Returns 1 on match. */
__device__ static int wpa_try_pmk(const uint8_t pmk[32]) {
    if (g_hs.eapol_len > 0) {
        uint8_t ptk[48], mic[16];
        wpa_ptk(pmk, g_hs.aa, g_hs.spa, g_hs.anonce, g_hs.snonce, ptk);
        wpa_eapol_mic(ptk, g_hs.eapol, g_hs.eapol_len, mic);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (mic[i] != g_hs.key_mic[i]) { ok = 0; break; }
        if (ok) return 1;
    }
    if (g_hs.have_pmkid) {
        uint8_t pmkid[16];
        wpa_pmkid(pmk, g_hs.pmkid_aa, g_hs.pmkid_spa, pmkid);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (pmkid[i] != g_hs.pmkid[i]) { ok = 0; break; }
        if (ok) return 1;
    }
    return 0;
}

#ifndef WPACRACK_CUDA_EMULATE
/* Real CUDA: kernel launch + host glue (excluded from host emulation, which
 * only needs the device crypto above). */

__global__ static void wpa_kernel(uint64_t start, uint64_t count,
                                  int *found, char *found_pw) {
    uint64_t idx = start + (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= start + count) return;
    if (*found) return;

    char pw[64];
    uint32_t n = g_npos;
    uint64_t x = idx;
    for (int k = (int)n - 1; k >= 0; k--) {
        pw[k] = g_cs[k][x % g_cslen[k]];
        x /= g_cslen[k];
    }
    pw[n] = 0;

    uint8_t pmk[32];
    pbkdf2_sha1((const uint8_t *)pw, n, g_hs.ssid, g_hs.ssid_len, 4096, pmk, 32);

    if (wpa_try_pmk(pmk)) {
        int old = atomicCAS(found, 0, 1);
        if (old == 0) {
            for (uint32_t i = 0; i <= n; i++) found_pw[i] = pw[i];
        }
    }
}

int gpu_device_count(void) {
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess) return 0;
    return n;
}

int gpu_device_name(int idx, char *buf, size_t n) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, idx) != cudaSuccess) return -1;
    snprintf(buf, n, "%s", prop.name);
    return 0;
}

/* Host-side helper to fill the __constant__ handshake + mask once. */
static void upload_constants(const gpu_ctx *ctx) {
    wpa_hs_d hs;
    memset(&hs, 0, sizeof(hs));
    const wpa_capture *cap = ctx->cap;
    hs.ssid_len = (uint32_t)cap->ssid_len;
    for (uint32_t i = 0; i < cap->ssid_len && i < 32; i++) hs.ssid[i] = cap->ssid[i];
    for (int i = 0; i < 6; i++) { hs.aa[i] = cap->aa[i]; hs.spa[i] = cap->spa[i]; }
    for (int i = 0; i < 32; i++) { hs.anonce[i] = cap->anonce[i]; hs.snonce[i] = cap->snonce[i]; }
    if (cap->have_eapol) {
        hs.eapol_len = (uint32_t)cap->eapol_len;
        for (uint32_t i = 0; i < cap->eapol_len && i < 192; i++) hs.eapol[i] = cap->eapol[i];
        for (int i = 0; i < 16; i++) hs.key_mic[i] = cap->key_mic[i];
    }
    if (cap->have_pmkid) {
        hs.have_pmkid = 1;
        for (int i = 0; i < 16; i++) hs.pmkid[i] = cap->pmkid[i];
        for (int i = 0; i < 6; i++) { hs.pmkid_aa[i] = cap->pmkid_aa[i]; hs.pmkid_spa[i] = cap->pmkid_spa[i]; }
    }
    cudaMemcpyToSymbol(g_hs, &hs, sizeof(hs));

    uint32_t npos = (uint32_t)ctx->mask->npos;
    cudaMemcpyToSymbol(g_npos, &npos, sizeof(npos));
    cudaMemcpyToSymbol(g_cslen, ctx->mask->cslen, sizeof(uint32_t) * NPOS_MAX);
    /* Flatten charsets into g_cs. */
    char flat[NPOS_MAX][256];
    memset(flat, 0, sizeof(flat));
    for (uint32_t p = 0; p < npos && p < NPOS_MAX; p++) {
        int l = ctx->mask->cslen[p];
        if (l > 255) l = 255;
        for (int i = 0; i < l; i++) flat[p][i] = ctx->mask->cs[p][i];
    }
    cudaMemcpyToSymbol(g_cs, flat, sizeof(flat));
}

int gpu_worker_process(gpu_ctx *ctx, int device_index) {
    if (device_index < 0) return -1;
    if (cudaSetDevice(device_index) != cudaSuccess) return -1;
    if (cudaGetLastError() != cudaSuccess) return -1;

    upload_constants(ctx);

    int *d_found;
    char *d_pw;
    cudaMalloc(&d_found, sizeof(int));
    cudaMalloc(&d_pw, 64);
    cudaMemset(d_found, 0, sizeof(int));
    cudaMemset(d_pw, 0, 64);

    uint64_t count = ctx->end - ctx->start;
    int threads = 256;
    uint64_t blocks = (count + threads - 1) / threads;
    if (blocks > 0x7fffffffULL) blocks = 0x7fffffffULL;

    /* Launch the whole chunk range at once. */
    for (uint64_t b = 0; b < blocks; ) {
        uint64_t blk = blocks - b;
        if (blk > 65535) blk = 65535;
        wpa_kernel<<<(unsigned)blk, threads>>>(ctx->start + b * threads, count, d_found, d_pw);
        b += blk;
        if (cudaGetLastError() != cudaSuccess) { ctx->done = count; break; }
    }
    cudaDeviceSynchronize();

    int h_found = 0;
    char h_pw[64];
    cudaMemcpy(&h_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_pw, d_pw, 64, cudaMemcpyDeviceToHost);
    cudaFree(d_found);
    cudaFree(d_pw);

    ctx->done = count;
    if (h_found) {
        ctx->found = 1;
        for (int i = 0; i < 64; i++) ctx->pw[i] = h_pw[i];
        return 1;
    }
    return 0;
}

#else /* WPACRACK_CUDA_EMULATE */

/* Host-emulation test entries: expose the device crypto to tests/test_gpu.c so
 * its algorithm can be verified against RFC vectors and a real capture without
 * an NVIDIA GPU. */

/* Fill the __constant__-style globals from a parsed capture (like the real
 * upload_constants does), so wpa_try_pmk_d sees the same handshake. */
static void gpu_emul_load_hs(const wpa_capture *cap) {
    memset(&g_hs, 0, sizeof(g_hs));
    g_hs.ssid_len = (uint32_t)cap->ssid_len;
    for (uint32_t i = 0; i < cap->ssid_len && i < 32; i++) g_hs.ssid[i] = cap->ssid[i];
    for (int i = 0; i < 6; i++) { g_hs.aa[i] = cap->aa[i]; g_hs.spa[i] = cap->spa[i]; }
    for (int i = 0; i < 32; i++) { g_hs.anonce[i] = cap->anonce[i]; g_hs.snonce[i] = cap->snonce[i]; }
    if (cap->have_eapol) {
        g_hs.eapol_len = (uint32_t)cap->eapol_len;
        for (uint32_t i = 0; i < cap->eapol_len && i < 192; i++) g_hs.eapol[i] = cap->eapol[i];
        for (int i = 0; i < 16; i++) g_hs.key_mic[i] = cap->key_mic[i];
    }
    if (cap->have_pmkid) {
        g_hs.have_pmkid = 1;
        for (int i = 0; i < 16; i++) g_hs.pmkid[i] = cap->pmkid[i];
        for (int i = 0; i < 6; i++) { g_hs.pmkid_aa[i] = cap->pmkid_aa[i]; g_hs.pmkid_spa[i] = cap->pmkid_spa[i]; }
    }
}

/* Device PBKDF2-HMAC-SHA1 (the exact function the kernel runs per candidate). */
int gpu_emul_pbkdf2(const uint8_t *pass, uint32_t passlen,
                    const uint8_t *salt, uint32_t saltlen,
                    uint32_t iters, uint8_t *dk, uint32_t dklen) {
    pbkdf2_sha1(pass, passlen, salt, saltlen, iters, dk, dklen);
    return 0;
}

/* Device PMK verification against the current handshake (1 = match). */
int gpu_emul_try_pmk(const uint8_t pmk[32], const wpa_capture *cap) {
    gpu_emul_load_hs(cap);
    return wpa_try_pmk(pmk);
}

#endif /* WPACRACK_CUDA_EMULATE */
