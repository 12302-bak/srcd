#ifndef WPACRACK_CRYPTO_H
#define WPACRACK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* HMAC-SHA1 (RFC 2104), one-shot, output exactly 20 bytes. */
void hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg,
               size_t msglen, uint8_t out[20]);

/* PBKDF2-HMAC-SHA1 (RFC 2898). */
void pbkdf2_sha1(const uint8_t *pass, size_t passlen, const uint8_t *salt,
                 size_t saltlen, uint32_t iters, uint8_t *dk, size_t dklen);

/* IEEE 802.11i PRF. outlen bytes produced from HMAC-SHA1. */
void wpa_prf(const uint8_t *key, size_t keylen, const uint8_t *label,
             size_t labellen, const uint8_t *data, size_t datalen,
             uint8_t *out, size_t outlen);

/* PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). */
void wpa_pmk(const uint8_t *pass, size_t passlen, const uint8_t *ssid,
             size_t ssidlen, uint8_t pmk[32]);

/* PTK = PRF-512(PMK, "Pairwise key expansion", min(AA,SPA)||max(AA,SPA)
 *   || min(ANonce,SNonce)||max(ANonce,SNonce)). */
void wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
             const uint8_t anonce[32], const uint8_t snonce[32],
             uint8_t ptk[48]);

/* EAPOL-Key MIC over an EAPOL frame whose MIC field is zeroed.
 * eapol points at the start of the EAPOL header (not the 802.11 frame).
 * Returns 16 bytes (first 16 of HMAC-SHA1-128 with KCK). */
void wpa_eapol_mic(const uint8_t kck[16], const uint8_t *eapol,
                   size_t eapol_len, uint8_t mic[16]);

/* PMKID = first 16 bytes of HMAC-SHA1(PMK, "PMK Name" || AA || SPA). */
void wpa_pmkid(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6],
               uint8_t pmkid[16]);

#endif
