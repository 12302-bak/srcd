#ifndef WPACRACK_WPA_H
#define WPACRACK_WPA_H

#include "pcap.h"

#include <stddef.h>
#include <stdint.h>

/* Derive PMK and check it against the capture. Returns 1 on match. */
int wpa_try_pass(const uint8_t *pass, size_t passlen, const wpa_capture *cap);

/* Check a precomputed PMK. Returns 1 on match. */
int wpa_try_pmk(const uint8_t pmk[32], const wpa_capture *cap);

#endif
