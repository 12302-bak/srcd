#include "../src/wpa.h"
#include "../src/crypto.h"
#include "../src/sha1.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    wpa_capture cap;
    if (argc < 2) { fprintf(stderr, "usage: %s <pcap>\n", argv[0]); return 2; }
    if (wpa_capture_from_pcap(argv[1], &cap) != 0) return 2;

    printf("ssid    : %.*s\n", (int)cap.ssid_len, cap.ssid);
    printf("have    : eapol=%d pmkid=%d\n", cap.have_eapol, cap.have_pmkid);
    if (cap.have_eapol) {
        printf("aa      : %02x%02x%02x%02x%02x%02x\n", cap.aa[0], cap.aa[1], cap.aa[2],
               cap.aa[3], cap.aa[4], cap.aa[5]);
        printf("spa     : %02x%02x%02x%02x%02x%02x\n", cap.spa[0], cap.spa[1], cap.spa[2],
               cap.spa[3], cap.spa[4], cap.spa[5]);
    }

    /* Known test password for aircrack-ng test/wpa.cap is "biscotte". */
    const char *p = (argc >= 3) ? argv[2] : "biscotte";
    int hit = wpa_try_pass((const uint8_t *)p, strlen(p), &cap);
    printf("password '%s' -> %s\n", p, hit ? "MATCH" : "no match");
    return hit ? 0 : 1;
}
