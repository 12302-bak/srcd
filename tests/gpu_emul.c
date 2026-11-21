/* Host-emulation shim: compile the CUDA device crypto as portable C so its
 * algorithm can be verified (tests/test_gpu.c) without an NVIDIA GPU or nvcc.
 * The emulation macro maps __device__/__global__/__constant__ to plain C and
 * excludes the kernel launch + cuda runtime glue.
 */
#define WPACRACK_CUDA_EMULATE
#include "../cu/gpu_cuda.cu"
