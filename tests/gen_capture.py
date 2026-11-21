#!/usr/bin/env python3
"""Generate a synthetic WPA2 handshake pcap with a known short password.
Used to exercise the full crack pipeline (parse -> mask -> workers -> found)
without an expensive keyspace. The crypto mirrors the verified C core."""
import hashlib, hmac, struct, random, sys

PASSWORD = b"1234"
SSID = b"test"
AA = bytes.fromhex("001122334455")   # AP / BSSID
SPA = bytes.fromhex("66778899aabb")   # STA
ANONCE = bytes.fromhex("a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8")
SNONCE = bytes.fromhex("e1e2e3e4e5e6e7e8f1f2f3f4f5f6f7f801020304050607081112131415161718")

def prf512(key, label, data):
    out = b""
    i = 0
    while len(out) < 64:
        # wpa_supplicant sha1_prf: label || 0x00 || data || counter
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:64]

pmk = hashlib.pbkdf2_hmac("sha1", PASSWORD, SSID, 4096, 32)
data = min(AA, SPA) + max(AA, SPA) + min(ANONCE, SNONCE) + max(ANONCE, SNONCE)
ptk = prf512(pmk, b"Pairwise key expansion", data)
kck = ptk[:16]

def eapol_key(nonce, keyinfo, mic_bytes):
    """Build an EAPOL-Key frame (version=1, type=3). mic_bytes = 16 or None."""
    body = bytearray()
    body += bytes([0x02])                      # descriptor type (RSN/WPA2)
    body += struct.pack(">H", keyinfo)         # key info
    body += struct.pack(">H", 0x0010)          # key length
    body += struct.pack(">Q", 0)               # replay counter
    body += nonce                              # nonce (32)
    body += bytes(16)                          # key IV
    body += bytes(8)                           # key RSC
    body += bytes(8)                           # key ID
    mic_off = len(body)
    body += bytes(16)                          # key MIC (zero for now)
    body += struct.pack(">H", 0)               # key data length
    # EAPOL header: version, type, length
    eapol = bytes([1, 3]) + struct.pack(">H", len(body)) + bytes(body)
    if mic_bytes is not None:
        # MIC over the whole EAPOL with the MIC field zeroed
        e = bytearray(eapol)
        e[4 + mic_off:4 + mic_off + 16] = bytes(16)
        mic = hmac.new(kck, bytes(e), hashlib.sha1).digest()[:16]
        e[4 + mic_off:4 + mic_off + 16] = mic
        eapol = bytes(e)
    return eapol

llc = bytes.fromhex("aaaa03000000888e")

def data_frame(fc, da, sa, bssid, payload):
    hdr = struct.pack("<H", fc) + struct.pack("<H", 0) + da + sa + bssid + struct.pack("<H", 0)
    return hdr + llc + payload

beacon_fc = (0 << 2) | (8 << 4)                      # type 0, sub 8
m1_fc = (2 << 2) | (0 << 4) | (1 << 9)               # data, FromDS=1 (AP->STA)
m2_fc = (2 << 2) | (0 << 4) | (1 << 8)               # data, ToDS=1   (STA->AP)
BCAST = bytes.fromhex("ffffffffffff")

beacon = struct.pack("<H", beacon_fc) + struct.pack("<H", 0) + BCAST + AA + AA + struct.pack("<H", 0)
beacon += bytes(8) + struct.pack("<H", 100) + struct.pack("<H", 0)   # timestamp, interval, caps
beacon += bytes([0, 4]) + SSID                        # SSID IE
beacon += bytes([48, 20]) + struct.pack(">H", 1) + bytes(4) + struct.pack(">H", 1) + bytes.fromhex("000fac04") + struct.pack(">H", 1) + bytes.fromhex("000fac02") + struct.pack(">H", 0)

m1 = data_frame(m1_fc, SPA, AA, AA, eapol_key(ANONCE, 0x0089, None))
m2 = data_frame(m2_fc, AA, SPA, AA, eapol_key(SNONCE, 0x010a, bytes(16)))

def pcap(linktype, packets):
    out = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    ts = 0
    for p in packets:
        out += struct.pack("<IIII", ts, 0, len(p), len(p)) + p
        ts += 1
    return out

packets = [beacon, m1, m2]
data = pcap(105, packets)   # DLT_IEEE802_11 (raw 802.11 frames)
with open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/syn.pcap", "wb") as f:
    f.write(data)
print("wrote", len(data), "bytes; password", PASSWORD.decode(), "ssid", SSID.decode())
