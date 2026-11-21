#include "crack.h"

#include <stdio.h>

/* Stub used when building without nvcc. The real implementation lives in
 * cu/gpu_cuda.cu and is compiled only when a CUDA toolkit is available. */

int gpu_device_count(void) { return 0; }

int gpu_device_name(int idx, char *buf, size_t n) {
    (void)idx;
    snprintf(buf, n, "CUDA support not built");
    return -1;
}

int gpu_worker_process(gpu_ctx *ctx, int device_index) {
    (void)ctx;
    (void)device_index;
    return -1; /* not supported in this build */
}
