# srcd — Simple Reasoning Calc Demo

A focused WPA/WPA2-PSK calc tool: **mask calc only**, running on the
**CPU and/or multiple NVIDIA CUDA GPUs simultaneously**, with runtime device
switching. It recovers the PSK key from a captured 4-way handshake or
PMKID.

This is a clean-room implementation: the crypto follows the public standards
(IEEE 802.11i, RFC 2898/2104/3174) and the reference PRF used by wpa_supplicant
— **not** the code of any existing
The CLI, file formats, mode numbering and kernel layout are its own.

## Build

```sh
# CPU only (works anywhere with a C compiler):
make                      # binaries -> build/srcd

# With CUDA (Linux + nvcc):
make cuda                 # builds ./build/srcd_cuda

# or CMake:
cmake -B build && cmake --build build
cmake -B build -DENABLE_CUDA=ON && cmake --build build   # with CUDA
```

All objects, dependency files and binaries land in `build/` (override with
`make BUILD=out`); `make clean` removes it.

If `make cuda` says `nvcc not found`, the CUDA toolkit is either missing or its
`bin/` is not on `PATH` (common on Kaggle, where it sits in `/usr/local/cuda/bin`).
The Makefile auto-probes the usual locations, but you can also point at it
directly: `make cuda NVCC=/usr/local/cuda/bin/nvcc`. With no toolkit at all, the
CPU binary still builds with plain `make`, and `make test` still validates the
device crypto through host emulation.

Run the unit tests (crypto against RFC 6070/2202/3174 vectors, WPA against a
real capture, mask expansion, and the CUDA device crypto verified via host
emulation):

```sh
make test
```

## Usage

```sh
# 8-digit PIN (WPA handshake)
./build/srcd --file handshake.pcap --mask '?d?d?d?d?d?d?d?d'

# 8-12 char lowercase, incremental
./build/srcd --file handshake.pcap --mask '?l' --increment 8-12

# custom charset, e.g. a specific PIN pattern
./build/srcd --file handshake.pcap --mask '?1?1?1?1?1?1' --1 '0123456789'

# custom charsets: ?1=?d?l (digits+lowercase), ?2=*!& ; single-dash -1..-4
./build/srcd --file handshake.pcap --mask '?1?2?s' -1 '?d?l' -2 '*!&'

# use CPU and GPUs (only the listed devices participate)
./build/srcd --file handshake.pcap --mask '?d?d?d?d?d?d?d?d' --device all
./build/srcd --file handshake.pcap --mask '?d?d?d?d?d?d?d?d' --device cpu
./build/srcd --file handshake.pcap --mask '?d?d?d?d?d?d?d?d' --device gpu
./build/srcd --file handshake.pcap --mask '?d?d?d?d?d?d?d?d' --device 'cpu,gpu0,gpu1'

# list available devices, then exit
./build/srcd --list-devices

# print the first 5 generated keys (no cracking), then exit
./build/srcd --preview 5 --mask '?d?d?d?d'
```

### Runtime device control

While running, press (single key, no Enter):

| key | action |
|-----|--------|
| `c` | toggle all CPU threads |
| `g` | toggle all GPUs |
| `1`-`9` | toggle a specific GPU |
| `q` | quit |

Devices that are toggled off finish their current work chunk, then idle until
re-enabled. Work is distributed by chunk stealing, so a faster device
automatically takes more work. The progress line shows the completed/total
candidate count, the rate, the **estimated time remaining (ETA)**, and the
**current key** being tested (`key[<index>] '<candidate>'`).

## Input

`--file` accepts a pcap with an 802.11 4-way handshake or a PMKID. Link types
supported: Ethernet (1), raw 802.11 (105), Prism (119), radiotap (127), AVS
(227). It extracts the SSID (from beacons), the authenticator/supplicant MACs,
both nonces, and the EAPOL-Key frame with its MIC (or the RSN-IE PMKID).

## Notes

- WPA-PSK calcing is a **dual-use** technique. Only test networks you are
  authorised to access.
- The CUDA path (`cu/gpu_cuda.cu`) mirrors the verified host crypto. It is
  compiled only with `nvcc` and has not been run on real NVIDIA hardware here,
  but its device algorithm is **verified by host emulation**: the same device
  crypto is compiled as portable C (`make test` runs `test_gpu`, see
  `tests/test_gpu.c`) and checked against RFC 6070 PBKDF2 vectors and the real
  `Induction` capture. Only the CUDA runtime glue (kernel launch,
  `cudaMemcpyToSymbol`, `atomicCAS`) is unexercised. The device kernel supports
  fixed-length positional masks only — an incremental mask (`--increment`)
  falls back to the CPU.
- Performance: CPU throughput is dominated by PBKDF2-HMAC-SHA1 (4096 rounds),
  roughly 50-150 candidates/s per core (a 16-thread run on an Apple Silicon Mac
  sustained ~750 candidates/s).
