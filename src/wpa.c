#include "wpa.h"
#include "crypto.h"

#include <string.h>

int wpa_try_pmk(const uint8_t pmk[32], const wpa_capture *cap) {
    if (cap->have_eapol) {
        uint8_t ptk[48];
        uint8_t mic[16];
        wpa_ptk(pmk, cap->aa, cap->spa, cap->anonce, cap->snonce, ptk);
        wpa_eapol_mic(ptk, cap->eapol, cap->eapol_len, mic);
        if (memcmp(mic, cap->key_mic, 16) == 0) return 1;
    }
    if (cap->have_pmkid) {
        uint8_t pmkid[16];
        wpa_pmkid(pmk, cap->pmkid_aa, cap->pmkid_spa, pmkid);
        if (memcmp(pmkid, cap->pmkid, 16) == 0) return 1;
    }
    return 0;
}

int wpa_try_pass(const uint8_t *pass, size_t passlen, const wpa_capture *cap) {
    uint8_t pmk[32];
    int hit;
    wpa_pmk(pass, passlen, cap->ssid, cap->ssid_len, pmk);
    hit = wpa_try_pmk(pmk, cap);
    return hit;
}
