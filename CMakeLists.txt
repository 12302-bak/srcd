cmake_minimum_required(VERSION 3.18)
project(srcd C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_CUDA "Build the CUDA backend" OFF)
find_package(Threads REQUIRED)

set(SRC
    src/sha1.c src/crypto.c src/pcap.c src/wpa.c src/mask.c src/crack.c
    src/main.c)

if(ENABLE_CUDA)
    enable_language(CUDA)
    list(APPEND SRC cu/gpu_cuda.cu)
    set_source_files_properties(cu/gpu_cuda.cu PROPERTIES LANGUAGE CUDA)
    message(STATUS "CUDA enabled: use `--device gpu` for NVIDIA GPUs")
else()
    list(APPEND SRC src/gpu_stub.c)
    message(STATUS "CUDA disabled (pass -DENABLE_CUDA=ON with nvcc to enable)")
endif()

add_executable(srcd ${SRC})
target_link_libraries(srcd PRIVATE Threads::Threads)

# Unit tests
enable_testing()
add_executable(test_crypto tests/test_crypto.c src/sha1.c src/crypto.c)
add_executable(test_wpa    tests/test_wpa.c src/sha1.c src/crypto.c src/pcap.c src/wpa.c)
add_executable(test_mask   tests/test_mask.c src/mask.c)
add_test(NAME crypto COMMAND test_crypto)
add_test(NAME wpa    COMMAND test_wpa /tmp/wi.pcap Induction)
add_test(NAME mask   COMMAND test_mask)
# Device-crypto host emulation (verifies the CUDA algorithm without a GPU).
# Only when the real CUDA backend is off, so the same .cu file isn't claimed
# by two languages in one build. tests/gpu_emul.c includes the .cu as plain C.
if(NOT ENABLE_CUDA)
    add_executable(test_gpu    tests/test_gpu.c tests/gpu_emul.c src/pcap.c src/wpa.c
                               src/sha1.c src/crypto.c)
    target_link_libraries(test_gpu PRIVATE Threads::Threads)
    add_test(NAME gpu COMMAND test_gpu)
endif()
