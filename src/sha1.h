#ifndef WPACRACK_SHA1_H
#define WPACRACK_SHA1_H

#include <stddef.h>
#include <stdint.h>

/* Streaming SHA-1 (FIPS 180-1 / RFC 3174). */
typedef struct {
    uint32_t h[5];
    uint64_t nbytes;
    uint8_t  buf[64];
    size_t   buflen;
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const void *data, size_t len);
void sha1_final(sha1_ctx *c, uint8_t out[20]);

/* One-shot SHA-1. */
void sha1(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
