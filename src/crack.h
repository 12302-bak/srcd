#ifndef WPACRACK_CRACK_H
#define WPACRACK_CRACK_H

#include "mask.h"
#include "pcap.h"

#include <pthread.h>
#include <stdint.h>

#define MAX_WORKERS 64

typedef struct crack_state {
    const wpa_capture *cap;
    const mask_t      *mask;
    uint64_t keyspace;
    uint64_t chunk;                 /* candidates per work unit        */
    uint64_t next_chunk;            /* next chunk to hand out (mutex)  */
    volatile int  found;
    volatile int  stop;             /* workers should stop (quit/done) */
    char     found_pw[64];
    int      found_len;
    pthread_mutex_t lock;
} crack_state;

typedef struct worker {
    crack_state *st;
    int   kind;                     /* 0 = CPU thread, 1 = CUDA device */
    int   id;                       /* worker index                     */
    volatile int *enabled;          /* shared enable flag               */
    volatile uint64_t done;         /* this worker's count (live)       */
    volatile uint64_t cur;          /* candidate index being tested now */
    pthread_t thread;
    int   active;
} worker;

void crack_init(crack_state *st, const wpa_capture *cap, const mask_t *mask,
                uint64_t chunk);
void *cpu_worker_main(void *arg);   /* runs a CPU worker thread         */
void *gpu_worker_main(void *arg);   /* runs a CUDA device worker thread */
void crack_stop(crack_state *st);   /* request all workers to stop      */
uint64_t crack_progress(const crack_state *st, const worker *ws, int n);

/* CUDA support (provided by cu/gpu_cuda.cu when built with nvcc, else stub). */
int  gpu_device_count(void);
int  gpu_device_name(int idx, char *buf, size_t n);
typedef struct gpu_ctx {
    const uint8_t *ssid; size_t ssid_len;
    const wpa_capture *cap;
    const mask_t *mask;
    uint64_t start, end;            /* candidate range for this chunk  */
    uint64_t done;
    int      found;
    char     pw[64];
} gpu_ctx;
int  gpu_worker_process(gpu_ctx *ctx, int device_index);

#endif
