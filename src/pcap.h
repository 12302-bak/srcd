#ifndef WPACRACK_PCAP_H
#define WPACRACK_PCAP_H

#include <stddef.h>
#include <stdint.h>

/* A WPA handshake / PMKID capture extracted from a pcap file. */
typedef struct {
    uint8_t  ssid[32];
    size_t   ssid_len;

    /* 4-way handshake (EAPOL-Key) */
    int      have_eapol;
    int      have_anonce;
    int      have_snonce;
    uint8_t  aa[6];            /* authenticator (AP) MAC */
    uint8_t  spa[6];           /* supplicant (STA) MAC  */
    uint8_t  anonce[32];
    uint8_t  snonce[32];
    uint8_t  key_mic[16];      /* MIC received in the frame  */
    uint8_t  eapol[300];       /* EAPOL-Key frame (incl. EAPOL header), MIC zeroed */
    size_t   eapol_len;

    /* PMKID (from RSN IE in EAPOL-Key key data) */
    int      have_pmkid;
    uint8_t  pmkid[16];
    uint8_t  pmkid_aa[6];      /* AA / SPA used in PMKID = HMAC(PMK, "PMK Name"||AA||SPA) */
    uint8_t  pmkid_spa[6];
} wpa_capture;

/* Parse a pcap file into `cap`. Returns 0 on success, -1 on error. */
int wpa_capture_from_pcap(const char *path, wpa_capture *cap);

#endif
