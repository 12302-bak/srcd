# srcd — Simple Reasoning Calc Demo: WPA/WPA2-PSK mask-attack cracker
# (CPU + optional CUDA).
#
# All build artifacts (objects, deps, binaries) go to build/, keeping the
# source tree clean.
#
#   make            build the host (CPU) binary and tests -> build/
#   make cuda       also build with CUDA (requires nvcc)
#   make test       run the unit tests
#   make clean      remove build/
#
# Override the output directory with: make BUILD=out

BUILD ?= build
CC    ?= cc
NVCC  ?= nvcc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS  := -lpthread

SRC := src/sha1.c src/crypto.c src/pcap.c src/wpa.c src/mask.c src/crack.c \
       src/main.c src/gpu_stub.c
OBJ := $(SRC:src/%.c=$(BUILD)/src/%.o)
DEP := $(OBJ:.o=.d)               # automatic header dependencies
CU_OBJ := $(BUILD)/cu/gpu_cuda.o

all: $(BUILD)/srcd tests

# ---- main binary ----
$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/srcd: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(BUILD)/src/%.o: src/%.c | $(BUILD)/src
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD)/src: | $(BUILD)
	mkdir -p $(BUILD)/src

# ---- tests (built directly, one binary each) ----
tests: $(BUILD)/test_crypto $(BUILD)/test_wpa $(BUILD)/test_mask $(BUILD)/test_gpu

$(BUILD)/test_crypto: tests/test_crypto.c src/sha1.c src/crypto.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/test_wpa: tests/test_wpa.c src/sha1.c src/crypto.c src/pcap.c src/wpa.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/test_mask: tests/test_mask.c src/mask.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^

# The CUDA device crypto is compiled as portable C (host emulation) so its
# algorithm can be verified without an NVIDIA GPU. See cu/gpu_cuda.cu.
$(BUILD)/test_gpu: tests/test_gpu.c tests/gpu_emul.c src/pcap.c src/wpa.c \
                   src/sha1.c src/crypto.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: tests
	$(BUILD)/test_crypto && $(BUILD)/test_mask && $(BUILD)/test_gpu && \
	if [ -f /tmp/wi.pcap ]; then $(BUILD)/test_wpa /tmp/wi.pcap Induction; \
	else echo "skip: test_wpa (no /tmp/wi.pcap)"; fi

# ---- CUDA (optional) ----
cuda: CFLAGS += -DHAVE_CUDA
cuda: $(BUILD)/srcd_cuda

$(BUILD)/srcd_cuda: $(SRC) $(CU_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(CU_OBJ) $(LDLIBS)

$(BUILD)/cu/gpu_cuda.o: cu/gpu_cuda.cu | $(BUILD)/cu
	$(NVCC) -O2 -c -o $@ $<

$(BUILD)/cu: | $(BUILD)
	mkdir -p $(BUILD)/cu

clean:
	rm -rf $(BUILD)

-include $(DEP)

.PHONY: all tests test cuda clean