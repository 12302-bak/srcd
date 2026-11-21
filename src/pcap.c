#include "pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p, int le) {
    return le ? (uint16_t)(p[0] | (p[1] << 8)) : (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t rd32(const uint8_t *p, int le) {
    return le ? (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24))
              : (uint32_t)(((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

/* ---- 802.11 management: extract SSID (IE 0) and PMKID (RSN IE 48) ---- */
static void parse_ies(const uint8_t *p, size_t n, wpa_capture *cap) {
    size_t i = 0;
    while (i + 2 <= n) {
        uint8_t id = p[i];
        uint8_t len = p[i + 1];
        if (i + 2 + len > n) break;
        if (id == 0 && len <= 32 && cap->ssid_len == 0) { /* SSID */
            if (len > 0 && !(len == 1 && p[i + 2] == 0)) { /* skip hidden SSID */
                memcpy(cap->ssid, p + i + 2, len);
                cap->ssid_len = len;
            }
        }
        /* RSN IE: version(2) group(4) pairwise cnt(2) pairwise akm cnt(2)
         * akm [caps(2)] [pmkid cnt(2) pmkid(16)] */
        if (id == 48 && len >= 20) {
            const uint8_t *r = p + i + 2;
            size_t rlen = len;
            size_t off = 2 + 4 + 2; /* version + group cipher + pairwise count */
            uint16_t pcnt = rd16(r + 6, 0);
            off += (size_t)pcnt * 4;
            uint16_t acnt = rd16(r + off, 0);
            off += 2 + (size_t)acnt * 4;
            if (off + 2 <= rlen) {
                uint16_t kcnt = rd16(r + off, 0);
                off += 2;
                if (kcnt >= 1 && off + 16 <= rlen) {
                    memcpy(cap->pmkid, r + off, 16);
                    cap->have_pmkid = 1;
                }
            }
        }
        i += 2 + len;
    }
}

/* ---- EAPOL-Key: extract nonce / MIC / RSN key data ---- */
static void parse_eapol_key(const uint8_t *eapol, size_t eapol_len,
                            int from_ap, const uint8_t *aa, const uint8_t *spa,
                            wpa_capture *cap) {
    const uint8_t *b = eapol + 4;
    size_t blen = eapol_len - 4;
    if (blen < 95) return;

    /* Key info is network-order; bit 3 = pairwise. Skip group-key frames. */
    uint16_t key_info = (uint16_t)((b[1] << 8) | b[2]);
    if (!(key_info & 0x0008)) return;

    /* EAPOL packet length is network-order (big-endian): eapol[2..3]. */
    uint16_t plen = (uint16_t)((eapol[2] << 8) | eapol[3]);
    size_t total = 4 + plen;
    if (total > eapol_len) total = eapol_len;

    const uint8_t *nonce = b + 13;      /* descriptor(1)+keyinfo(2)+keylen(2)+replay(8)=13 */
    const uint8_t *mic   = b + 77;      /* +nonce(32)+iv(16)+rsc(8)+id(8) = 77 */

    /* Capture the first non-zero nonce from each direction (don't overwrite). */
    {
        uint8_t nz = 0;
        for (int i = 0; i < 32; i++) nz |= nonce[i];
        if (nz) {
            if (from_ap && !cap->have_anonce) {
                memcpy(cap->anonce, nonce, 32);
                cap->have_anonce = 1;
            } else if (!from_ap && !cap->have_snonce) {
                memcpy(cap->snonce, nonce, 32);
                cap->have_snonce = 1;
            }
        }
    }

    /* A frame carries a MIC when the field is non-zero; pick the first one
     * and remember the authenticator/supplicant MACs that go with it. */
    {
        uint8_t micsum = 0;
        for (int i = 0; i < 16; i++) micsum |= mic[i];
        if (micsum && !cap->have_eapol) {
            size_t copy = total < sizeof(cap->eapol) ? total : sizeof(cap->eapol);
            memcpy(cap->eapol, eapol, copy);
            cap->eapol_len = copy;
            memset(cap->eapol + 4 + 77, 0, 16); /* zero MIC */
            memcpy(cap->key_mic, mic, 16);
            memcpy(cap->aa, aa, 6);
            memcpy(cap->spa, spa, 6);
            cap->have_eapol = 1;
        }
    }

    /* PMKID lives in the RSN IE inside key data (EAPOL-Key M1). */
    {
        uint16_t kdlen = (uint16_t)((b[93] << 8) | b[94]); /* network-order */
        const uint8_t *kd = b + 95;
        if (93 + 2 + kdlen <= blen) {
            parse_ies(kd, kdlen, cap);
            if (cap->have_pmkid && cap->pmkid_aa[0] == 0) {
                memcpy(cap->pmkid_aa, aa, 6);
                memcpy(cap->pmkid_spa, spa, 6);
            }
        }
    }
}

/* ---- per-802.11-frame handling ---- */
static void handle_frame(const uint8_t *f, size_t flen, int le, wpa_capture *cap) {
    if (flen < 10) return;
    uint16_t fc = rd16(f, le);
    uint8_t type = (fc >> 2) & 3;
    uint8_t subtype = (fc >> 4) & 0xf;

    if (type == 0) { /* management */
        /* fixed params at offset 24; IEs follow */
        size_t ie_off = 24;
        /* management header: fc(2) dur(2) addr1(6) addr2(6) addr3(6) seq(2) = 24 */
        if (subtype == 0x8 || subtype == 0x5) { /* beacon / probe resp */
            ie_off = 24 + 12; /* + timestamp(8) + interval(2) + caps(2) */
        } else if (subtype == 0x0 || subtype == 0x1) { /* (re)assoc req */
            ie_off = 24 + 10; /* + caps(2) + listen(2) + current ap(6) */
        } else {
            return;
        }
        if (ie_off < flen) parse_ies(f + ie_off, flen - ie_off, cap);
        return;
    }

    if (type != 2) return; /* data only */
    if (subtype != 0x0 && subtype != 0x8) return; /* plain / QoS data */

    int qos = (subtype == 0x8);
    size_t hdr = 24 + (qos ? 2 : 0);
    size_t body = hdr + 8; /* LLC/SNAP */
    if (body + 4 > flen) return;

    int tods = (fc >> 8) & 1;
    int fromds = (fc >> 9) & 1;
    const uint8_t *addr1 = f + 4, *addr2 = f + 10, *addr3 = f + 16;
    const uint8_t *aa, *spa;
    if (tods) { aa = addr3; spa = addr2; }
    else      { aa = addr2; spa = addr1; }

    /* LLC/SNAP: AA AA 03 00 00 00 88 8e (EAPOL) */
    if (f[body - 8] != 0xaa || f[body - 7] != 0xaa || f[body - 6] != 0x03 ||
        f[body - 2] != 0x88 || f[body - 1] != 0x8e)
        return;

    const uint8_t *eapol = f + body;
    size_t eapol_len = flen - body;
    if (eapol_len < 4) return;
    if (eapol[1] != 3) return; /* type 3 = Key */

    int from_ap = fromds; /* AP is transmitter when FromDS set */
    parse_eapol_key(eapol, eapol_len, from_ap, aa, spa, cap);
}

int wpa_capture_from_pcap(const char *path, wpa_capture *cap) {
    FILE *fp = fopen(path, "rb");
    uint8_t gh[24];
    if (!fp) { perror(path); return -1; }
    if (fread(gh, 1, 24, fp) != 24) { fclose(fp); return -1; }

    memset(cap, 0, sizeof(*cap));

    int le;
    uint32_t magic = rd32(gh, 1); /* read as little-endian */
    if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) le = 1;       /* bytes d4c3b2a1: little-endian */
    else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) le = 0;  /* bytes a1b2c3d4: big-endian  */
    else { fclose(fp); fprintf(stderr, "unknown pcap magic\n"); return -1; }

    uint32_t linktype = rd32(gh + 20, le);

    uint8_t rec[16];
    while (fread(rec, 1, 16, fp) == 16) {
        uint32_t incl = rd32(rec + 8, le);
        if (incl == 0 || incl > 65535) continue;
        uint8_t *data = malloc(incl);
        if (!data) break;
        if (fread(data, 1, incl, fp) != incl) { free(data); break; }

        size_t off = 0;
        switch (linktype) {
        case 1:   off = 14; break;                      /* Ethernet */
        case 105: off = 0;  break;                      /* IEEE802.11 raw */
        case 127:                                        /* Radiotap */
            if (incl >= 8) off = rd16(data + 2, 1);
            break;
        case 119:                                        /* Prism header */
            if (incl >= 8) off = rd32(data + 4, 1);
            break;
        case 227:                                        /* AVS (radiotap-ish) */
            if (incl >= 8) off = 64;
            break;
        default: off = 0; break;
        }

        if (off < incl) handle_frame(data + off, incl - off, le, cap);
        free(data);

        if (cap->have_eapol && cap->have_pmkid && cap->ssid_len) break;
    }
    fclose(fp);
    if (cap->ssid_len == 0) {
        fprintf(stderr, "warning: no SSID found in capture\n");
    }
    if (!cap->have_eapol && !cap->have_pmkid) {
        fprintf(stderr, "warning: no WPA handshake or PMKID found\n");
    }
    return 0;
}
