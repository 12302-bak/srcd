#include "crack.h"
#include "wpa.h"

#include <string.h>
#include <time.h>

void crack_init(crack_state *st, const wpa_capture *cap, const mask_t *mask,
                uint64_t chunk) {
    memset(st, 0, sizeof(*st));
    st->cap = cap;
    st->mask = mask;
    st->keyspace = mask->keyspace;
    st->chunk = chunk ? chunk : 1000000;
    st->next_chunk = 0;
    pthread_mutex_init(&st->lock, NULL);
}

void crack_stop(crack_state *st) {
    pthread_mutex_lock(&st->lock);
    st->stop = 1; /* workers stop; `found` is set only on an actual match */
    pthread_mutex_unlock(&st->lock);
}

void *cpu_worker_main(void *arg) {
    worker *w = (worker *)arg;
    crack_state *st = w->st;
    char pw[64];

    while (1) {
        int should_stop;
        pthread_mutex_lock(&st->lock);
        should_stop = st->stop || st->found;
        pthread_mutex_unlock(&st->lock);
        if (should_stop) break;

        if (w->enabled && !*w->enabled) {
            struct timespec ts = {0, 50 * 1000000};
            nanosleep(&ts, NULL);
            continue;
        }

        /* Grab a chunk. */
        uint64_t start;
        pthread_mutex_lock(&st->lock);
        start = st->next_chunk;
        if (start < st->keyspace) {
            st->next_chunk = start + st->chunk;
        } else {
            st->next_chunk = start; /* exhausted */
        }
        pthread_mutex_unlock(&st->lock);

        if (start >= st->keyspace) {
            struct timespec ts = {0, 50 * 1000000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t end = start + st->chunk;
        if (end > st->keyspace) end = st->keyspace;

        for (uint64_t idx = start; idx < end; idx++) {
            if (st->stop || st->found) break; /* quit or another worker found it */
            w->cur = idx;                     /* publish current candidate     */
            mask_candidate(st->mask, idx, pw);
            int len = (int)strlen(pw);
            if (wpa_try_pass((const uint8_t *)pw, (size_t)len, st->cap)) {
                pthread_mutex_lock(&st->lock);
                if (!st->found) {
                    st->found = 1;
                    memcpy(st->found_pw, pw, (size_t)len + 1);
                    st->found_len = len;
                }
                pthread_mutex_unlock(&st->lock);
                break;
            }
            w->done++; /* live counter (volatile); updated per candidate */
        }
    }
    return NULL;
}

uint64_t crack_progress(const crack_state *st, const worker *ws, int n) {
    (void)st;
    uint64_t total = 0;
    for (int i = 0; i < n; i++) total += ws[i].done;
    return total;
}

/* GPU device worker: grabs chunks like the CPU workers, hands each chunk to
 * the CUDA backend (cu/gpu_cuda.cu), and reports results. */
void *gpu_worker_main(void *arg) {
    worker *w = (worker *)arg;
    crack_state *st = w->st;

    while (1) {
        int should_stop;
        pthread_mutex_lock(&st->lock);
        should_stop = st->stop || st->found;
        pthread_mutex_unlock(&st->lock);
        if (should_stop) break;

        if (w->enabled && !*w->enabled) {
            struct timespec ts = {0, 100 * 1000000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t start;
        pthread_mutex_lock(&st->lock);
        start = st->next_chunk;
        if (start < st->keyspace) st->next_chunk = start + st->chunk;
        pthread_mutex_unlock(&st->lock);

        if (start >= st->keyspace) {
            struct timespec ts = {0, 100 * 1000000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t end = start + st->chunk;
        if (end > st->keyspace) end = st->keyspace;

        w->cur = start; /* publish the frontier now; the kernel may run for seconds */

        gpu_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ssid = st->cap->ssid;
        ctx.ssid_len = st->cap->ssid_len;
        ctx.cap = st->cap;
        ctx.mask = st->mask;
        ctx.start = start;
        ctx.end = end;

        if (gpu_worker_process(&ctx, w->id) == 1) {
            pthread_mutex_lock(&st->lock);
            if (!st->found) {
                st->found = 1;
                memcpy(st->found_pw, ctx.pw, 64);
                st->found_len = (int)strlen(ctx.pw);
            }
            pthread_mutex_unlock(&st->lock);
        }

        w->cur = ctx.end; /* GPU processed the whole chunk */
        w->done += ctx.done;
    }
    return NULL;
}
