#include "crack.h"
#include "mask.h"
#include "pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --file <capture.pcap> --mask <mask> [options]\n"
        "\n"
        "WPA/WPA2-PSK calc with mask attack on CPU and/or NVIDIA CUDA GPUs.\n"
        "\n"
        "required:\n"
        "  --file <pcap>           capture file (.pcap) with a 4-way handshake\n"
        "                          or a PMKID (Ethernet / radiotap / prism links)\n"
        "  --mask <mask>           e.g. '?d?d?d?d?d?d?d?d' or '?d?d?d?d?d?d?d?d?d'\n"
        "\n"
        "options:\n"
        "  --device <list>         cpu, gpu, all, or a mix e.g. 'cpu,gpu0,gpu1'\n"
        "                          (default: all available)\n"
        "  --threads <n>           CPU threads (default: number of cores)\n"
        "  --1 .. --4 <charset>    custom charsets for ?1-?4 (e.g. '0123456789')\n"
        "  --increment <min-max>   incremental length, e.g. 4-8 (mask is one\n"
        "                          charset token such as '?d')\n"
        "  --chunk <n>             candidates per work unit (default 1000000)\n"
        "  --status <sec>          progress refresh interval (default 5)\n"
        "  --quiet                 suppress progress output\n"
        "  --preview <n>           print the first n generated keys and exit\n"
        "                          (no cracking is performed)\n"
        "  --list-devices          list available CPU threads and CUDA GPUs\n"
        "                          and exit\n"
        "\n"
        "runtime keys (stdin):\n"
        "  c  toggle CPU   g  toggle all GPUs   1-9 toggle GPU n   q  quit\n",
        prog);
}

int main(int argc, char **argv) {
    const char *file = NULL, *maskstr = NULL, *devstr = "all";
    const char *custom[4] = { NULL, NULL, NULL, NULL };
    int inc_min = 0, inc_max = 0;
    int threads = 0, status_sec = 5, quiet = 0;
    int preview = -1, list_devices = 0;
    uint64_t chunk = 1000000;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--file") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(argv[i], "--mask") && i + 1 < argc) maskstr = argv[++i];
        else if (!strcmp(argv[i], "--device") && i + 1 < argc) devstr = argv[++i];
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--chunk") && i + 1 < argc) chunk = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--status") && i + 1 < argc) status_sec = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else if (!strcmp(argv[i], "--preview") && i + 1 < argc) preview = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--list-devices")) list_devices = 1;
        else if (!strcmp(argv[i], "--increment") && i + 1 < argc) {
            if (sscanf(argv[++i], "%d-%d", &inc_min, &inc_max) != 2) { usage(argv[0]); return 2; }
        }
        else if (!strncmp(argv[i], "--", 2) && strlen(argv[i]) == 3 &&
                 argv[i][2] >= '1' && argv[i][2] <= '4' && i + 1 < argc) {
            custom[argv[i][2] - '1'] = argv[i + 1];
            i++;
        }
        else { usage(argv[0]); return 2; }
    }

    /* --list-devices: show CPU cores and each CUDA GPU, then exit. */
    if (list_devices) {
        long ncores = sysconf(_SC_NPROCESSORS_ONLN);
        int ng = gpu_device_count();
        printf("CPU threads: %ld\n", ncores > 0 ? ncores : 1);
        if (ng > 0) {
            for (int g = 0; g < ng; g++) {
                char name[128] = "";
                if (gpu_device_name(g, name, sizeof(name)) != 0) snprintf(name, sizeof(name), "?");
                printf("GPU %d      : %s\n", g, name);
            }
        } else {
            printf("CUDA GPUs  : 0 (none, or this build has no CUDA support)\n");
        }
        return 0;
    }

    if (!maskstr) { usage(argv[0]); return 2; }

    /* --preview N: print the first N generated keys (no cracking). */
    if (preview >= 0) {
        mask_t m;
        if (mask_parse(&m, maskstr, custom[0], custom[1], custom[2], custom[3],
                       inc_min, inc_max) != 0) {
            fprintf(stderr, "error: bad mask '%s'\n", maskstr);
            return 1;
        }
        uint64_t n = m.keyspace;
        if ((uint64_t)preview < n) n = (uint64_t)preview;
        for (uint64_t k = 0; k < n; k++) {
            char pw[64];
            mask_candidate(&m, k, pw);
            printf("%s\n", pw);
        }
        return 0;
    }

    if (!file) { usage(argv[0]); return 2; }

    wpa_capture cap;
    if (wpa_capture_from_pcap(file, &cap) != 0) return 1;
    if (!cap.have_eapol && !cap.have_pmkid) {
        fprintf(stderr, "error: no usable WPA handshake or PMKID in %s\n", file);
        return 1;
    }
    if (cap.have_pmkid && !cap.have_eapol && cap.pmkid_aa[0] == 0) {
        fprintf(stderr, "error: PMKID present but no AA/SPA (need a handshake too)\n");
        return 1;
    }

    mask_t mask;
    if (mask_parse(&mask, maskstr, custom[0], custom[1], custom[2], custom[3],
                   inc_min, inc_max) != 0) {
        fprintf(stderr, "error: bad mask '%s'\n", maskstr);
        return 1;
    }

    int ngpu = gpu_device_count();
    int use_cpu = 0, use_gpu = 0;
    if (!strcmp(devstr, "cpu")) use_cpu = 1;
    else if (!strcmp(devstr, "gpu")) use_gpu = 1;
    else if (!strcmp(devstr, "all")) { use_cpu = 1; use_gpu = ngpu > 0; }
    else {
        /* "cpu,gpu0,gpu1" style */
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", devstr);
        char *tok = strtok(buf, ",");
        while (tok) {
            if (!strcmp(tok, "cpu")) use_cpu = 1;
            else if (!strncmp(tok, "gpu", 3)) use_gpu = 1;
            tok = strtok(NULL, ",");
        }
    }
    if (!use_cpu && !use_gpu) { fprintf(stderr, "error: no device selected\n"); return 1; }
    if (use_gpu && ngpu == 0) {
        fprintf(stderr, "warning: no CUDA devices found; GPU disabled\n");
        use_gpu = 0;
    }
    if (use_gpu && mask.incremental) {
        /* The CUDA kernel is positional-only; incremental lengths need the
         * CPU mask_candidate walk. Fall back to CPU rather than silently
         * generating empty candidates on the GPU. */
        fprintf(stderr, "warning: incremental mask unsupported on GPU; GPU disabled\n");
        use_gpu = 0;
    }

    /* Build the worker table. */
    worker workers[MAX_WORKERS];
    int nw = 0;
    crack_state st;
    crack_init(&st, &cap, &mask, chunk);

    volatile int cpu_enabled = 1;
    volatile int gpu_enabled[MAX_WORKERS];

    if (use_cpu) {
        if (threads <= 0) {
            threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
            if (threads <= 0) threads = 4;
        }
        for (int i = 0; i < threads && nw < MAX_WORKERS; i++) {
            workers[nw].st = &st;
            workers[nw].kind = 0;
            workers[nw].id = nw;
            workers[nw].enabled = &cpu_enabled;
            workers[nw].done = 0;
            workers[nw].cur = 0;
            workers[nw].active = 1;
            nw++;
        }
    }
    for (int g = 0; g < ngpu && nw < MAX_WORKERS; g++) {
        gpu_enabled[g] = 1;
        workers[nw].st = &st;
        workers[nw].kind = 1;
        workers[nw].id = g;
        workers[nw].enabled = &gpu_enabled[g];
        workers[nw].done = 0;
        workers[nw].cur = 0;
        workers[nw].active = 1;
        nw++;
    }

    /* Adaptive chunk size: keep every worker busy on small keyspaces. */
    if (mask.keyspace > 0) {
        uint64_t target = mask.keyspace / ((uint64_t)nw * 8);
        if (target < st.chunk) st.chunk = target;
        if (st.chunk < 1) st.chunk = 1;
    }

    printf("Name    : %.*s\n", (int)cap.ssid_len, cap.ssid);
    printf("Target  : %s\n", cap.have_eapol ? "EAPOL 4-way handshake" : "PMKID");
    printf("Mask    : %s\n", maskstr);
    printf("Keyspace: %llu\n", (unsigned long long)mask.keyspace);
    printf("Devices : ");
    if (use_cpu) printf("%d CPU thread(s) ", threads);
    if (use_gpu) printf("%d GPU(s)", ngpu);
    printf("\n");
    printf("Press c/g/1-9 to toggle devices, q to quit.\n");

    /* Spawn workers. */
    for (int i = 0; i < nw; i++) {
        pthread_create(&workers[i].thread, NULL,
                       workers[i].kind == 0 ? cpu_worker_main : gpu_worker_main,
                       &workers[i]);
    }

    /* Input thread: single-key runtime device toggling (only on a TTY). */
    struct termios oldt, newt;
    int tty = isatty(STDIN_FILENO);
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }

    time_t prev_t = time(NULL);
    time_t start_t = prev_t;     /* rate is measured over the whole run, not per tick */
    int running = 1;

    while (running) {
        /* Handle keys. */
        char c;
        while (read(STDIN_FILENO, &c, 1) == 1) {
            if (c == 'q') { crack_stop(&st); running = 0; }
            else if (c == 'c') { cpu_enabled = !cpu_enabled; printf("\n[CPU %s]\n", cpu_enabled ? "ON" : "OFF"); }
            else if (c == 'g') {
                for (int g = 0; g < ngpu; g++) gpu_enabled[g] = !gpu_enabled[g];
                printf("\n[GPU %s]\n", gpu_enabled[0] ? "ON" : "OFF");
            }
            else if (c >= '1' && c <= '9') {
                int g = c - '1';
                if (g < ngpu) { gpu_enabled[g] = !gpu_enabled[g]; printf("\n[GPU%d %s]\n", g, gpu_enabled[g] ? "ON" : "OFF"); }
            }
            fflush(stdout);
        }

        if (st.found) { running = 0; }

        uint64_t done = crack_progress(&st, workers, nw);

        /* Progress. */
        time_t now = time(NULL);
        if (now - prev_t >= status_sec) {
            /* Rate averaged over the whole run. Per-tick rates jump between 0
             * and a real value with several devices, since a fast GPU finishes
             * a whole chunk in one tick and idles the next; cumulative never dips. */
            time_t elapsed = now - start_t;
            uint64_t rate = elapsed > 0 ? done / (uint64_t)elapsed : 0;
            double pct = st.keyspace ? 100.0 * (double)done / (double)st.keyspace : 0.0;

            /* Estimated remaining time from the current rate. */
            uint64_t rem = st.keyspace > done ? st.keyspace - done : 0;
            uint64_t eta_s = rate ? rem / rate : 0;
            char etabuf[32];
            if (!rate)
                snprintf(etabuf, sizeof(etabuf), "-");
            else
                snprintf(etabuf, sizeof(etabuf), "%llu:%02llu:%02llu",
                         (unsigned long long)(eta_s / 3600),
                         (unsigned long long)((eta_s % 3600) / 60),
                         (unsigned long long)(eta_s % 60));

            /* Current key: the most advanced worker's candidate in flight. */
            uint64_t maxcur = 0;
            for (int i = 0; i < nw; i++) if (workers[i].cur > maxcur) maxcur = workers[i].cur;
            if (st.keyspace && maxcur >= st.keyspace) maxcur = st.keyspace - 1;
            char curpw[64] = "";
            if (st.keyspace) mask_candidate(&mask, maxcur, curpw);

            if (!quiet) {
                printf("\rprogress: %llu / %llu (%.1f%%)  %llu H/s  ETA %s  key[%llu] '%s'      ",
                       (unsigned long long)done, (unsigned long long)st.keyspace,
                       pct, (unsigned long long)rate, etabuf,
                       (unsigned long long)maxcur, curpw);
                fflush(stdout);
            }
            prev_t = now;
        }

        /* Completion: all chunks handed out and every candidate counted. */
        int exhausted;
        pthread_mutex_lock(&st.lock);
        exhausted = (st.next_chunk >= st.keyspace && done >= st.keyspace);
        pthread_mutex_unlock(&st.lock);
        if (exhausted) break;

        struct timespec ts = {0, 200 * 1000000};
        nanosleep(&ts, NULL);
    }

    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fcntl(STDIN_FILENO, F_SETFL, flags);
    }

    crack_stop(&st);
    for (int i = 0; i < nw; i++) pthread_join(workers[i].thread, NULL);

    printf("\n");
    if (st.found) {
        printf("FOUND: %s\n", st.found_pw);
        return 0;
    } else {
        printf("NOT FOUND (keyspace exhausted)\n");
        return 1;
    }
}
