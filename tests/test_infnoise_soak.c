// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// 24-hour (configurable) soak test for the Infinite Noise TRNG OpenSSL
// provider.  Exercises the provider code directly through EVP_RAND for
// the full duration — every byte consumed passes through our dispatch,
// our spill buffer, and our three-phase generate().
//
// What it stresses:
//   - Request size variety (1, 63, 64, 65, 127, 128, 129, 4096, 1 MiB,
//     random) — hits every spill-buffer phase boundary on every cycle.
//   - Periodic full lifecycle churn (uninstantiate / instantiate) to
//     exercise context reuse and USB reopen paths.
//   - RSS sampling to catch slow leaks.
//   - Periodic sample dumps for offline ent / rngtest / dieharder.
//   - Clean shutdown on SIGINT/SIGTERM with final summary.
//
// Build:
//   make test-soak
//
// Run (default 24 h):
//   OPENSSL_CONF=conf/infnoise-provider.cnf ./test_infnoise_soak
//
// Run shorter (env override, seconds):
//   SOAK_SECONDS=3600 ./test_infnoise_soak
//
// Sample directory (optional, defaults to /tmp/infnoise-soak-<pid>):
//   SOAK_SAMPLE_DIR=/var/tmp/soak ./test_infnoise_soak

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64
#define MAX_REQ (1u << 20)  // 1 MiB — matches provider INFNOISE_MAX_REQUEST

// Size mix designed to hit every spill-buffer boundary on every cycle.
// Phase 1 (drain spill), Phase 2 (direct batch), Phase 3 (tail + stash).
static const size_t size_mix[] = {
    1, 7, 31, 63, 64, 65, 96, 127, 128, 129,
    255, 256, 257, 1024, 4096, 16384, 65536, 262144, 1048576
};
#define SIZE_MIX_N (sizeof(size_mix) / sizeof(size_mix[0]))

static volatile sig_atomic_t stop_flag = 0;
static void on_signal(int sig) { (void)sig; stop_flag = 1; }

// RSS in kB from /proc/self/statm (field 2 = resident pages).
static long rss_kb(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long size_pages, resident_pages;
    if (fscanf(f, "%ld %ld", &size_pages, &resident_pages) != 2) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return resident_pages * (sysconf(_SC_PAGESIZE) / 1024);
}

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "FATAL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    ERR_print_errors_fp(stderr);
    exit(2);
}

int main(void) {
    long soak_seconds = 86400;
    const char *env = getenv("SOAK_SECONDS");
    if (env) {
        char *endp;
        long v = strtol(env, &endp, 10);
        if (*endp == '\0' && v > 0) soak_seconds = v;
    }

    char sample_dir[512];
    const char *sd = getenv("SOAK_SAMPLE_DIR");
    if (sd) {
        snprintf(sample_dir, sizeof(sample_dir), "%s", sd);
    } else {
        snprintf(sample_dir, sizeof(sample_dir), "/tmp/infnoise-soak-%d", (int)getpid());
    }
    if (mkdir(sample_dir, 0700) != 0 && errno != EEXIST) {
        die("mkdir %s: %s", sample_dir, strerror(errno));
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("==== infnoise provider soak test ====\n");
    printf("duration:     %ld seconds (%.2f hours)\n",
           soak_seconds, soak_seconds / 3600.0);
    printf("sample dir:   %s\n", sample_dir);
    printf("max request:  %u bytes\n", MAX_REQ);
    printf("pid:          %d\n", (int)getpid());
    printf("send SIGINT (Ctrl-C) or SIGTERM for early clean shutdown\n\n");
    fflush(stdout);

    // Fetch provider's EVP_RAND (relies on OPENSSL_CONF).
    EVP_RAND *rand_algo = EVP_RAND_fetch(NULL, "infnoise", NULL);
    if (!rand_algo) die("EVP_RAND_fetch(infnoise) failed — is OPENSSL_CONF set?");

    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand_algo, NULL);
    if (!ctx) die("EVP_RAND_CTX_new failed");

    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, NULL))
        die("EVP_RAND_instantiate failed");

    unsigned char *buf = malloc(MAX_REQ);
    if (!buf) die("malloc failed");

    uint64_t total_bytes   = 0;
    uint64_t total_calls   = 0;
    uint64_t total_errors  = 0;
    uint64_t churn_cycles  = 0;
    uint64_t samples_dumped = 0;

    const double t0        = mono_now();
    const double deadline  = t0 + (double)soak_seconds;
    double next_log        = t0 + 60.0;        // log every minute
    double next_sample     = t0 + 300.0;       // sample every 5 min
    double next_churn      = t0 + 900.0;       // churn every 15 min
    long   rss_start       = rss_kb();
    long   rss_peak        = rss_start;

    FILE *sample_fp = NULL;

    size_t mix_idx = 0;
    while (!stop_flag) {
        double now = mono_now();
        if (now >= deadline) break;

        // Pick next size: alternate mix-sweep and random size for variety.
        size_t want;
        if ((total_calls & 1) == 0) {
            want = size_mix[mix_idx];
            mix_idx = (mix_idx + 1) % SIZE_MIX_N;
        } else {
            // Non-crypto rand is fine here — just picking a size.
            want = (size_t)((rand() % MAX_REQ) + 1);
        }

        if (!EVP_RAND_generate(ctx, buf, want, 256, 0, NULL, 0)) {
            total_errors++;
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "generate failed at call %" PRIu64 ", size %zu\n",
                    total_calls, want);
            // On repeated errors, bail.
            if (total_errors > 10) die("too many generate errors");
            // Brief pause then continue — transient USB glitches happen.
            usleep(100000);
            continue;
        }
        total_calls++;
        total_bytes += want;

        // Write some output to a rolling sample file for offline analysis.
        if (sample_fp && want >= BATCH) {
            fwrite(buf, 1, want, sample_fp);
        }

        // Periodic progress log.
        if (now >= next_log) {
            long rss = rss_kb();
            if (rss > rss_peak) rss_peak = rss;
            double elapsed = now - t0;
            double mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed;
            printf("[t=%8.0fs] calls=%-10" PRIu64 " bytes=%-12" PRIu64
                   " %.2f MiB/s errs=%" PRIu64
                   " churn=%" PRIu64 " rss=%ldkB (Δ%+ldkB)\n",
                   elapsed, total_calls, total_bytes, mbps, total_errors,
                   churn_cycles, rss, rss - rss_start);
            fflush(stdout);
            next_log = now + 60.0;
        }

        // Periodic sample file rotation (for ent / rngtest / dieharder).
        if (now >= next_sample) {
            if (sample_fp) { fclose(sample_fp); sample_fp = NULL; }
            char path[640];
            snprintf(path, sizeof(path), "%s/sample-%06" PRIu64 ".bin",
                     sample_dir, samples_dumped);
            sample_fp = fopen(path, "wb");
            if (!sample_fp) {
                fprintf(stderr, "warn: cannot open %s: %s\n", path, strerror(errno));
            } else {
                samples_dumped++;
            }
            next_sample = now + 300.0;
        }

        // Periodic full lifecycle churn: uninstantiate + re-instantiate.
        // Exercises USB close/reopen, context reset, spill cleanse.
        if (now >= next_churn) {
            if (!EVP_RAND_uninstantiate(ctx)) die("uninstantiate failed");
            if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, NULL))
                die("re-instantiate failed");
            churn_cycles++;
            next_churn = now + 900.0;
        }
    }

    if (sample_fp) fclose(sample_fp);

    double elapsed = mono_now() - t0;
    long rss_end = rss_kb();
    if (rss_end > rss_peak) rss_peak = rss_end;

    EVP_RAND_uninstantiate(ctx);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(rand_algo);
    free(buf);

    printf("\n==== soak test complete ====\n");
    printf("duration:       %.1f s (%.2f h)\n", elapsed, elapsed / 3600.0);
    printf("generate calls: %" PRIu64 "\n", total_calls);
    printf("bytes produced: %" PRIu64 " (%.2f MiB)\n",
           total_bytes, total_bytes / (1024.0 * 1024.0));
    printf("avg throughput: %.2f KiB/s\n",
           (total_bytes / 1024.0) / (elapsed > 0 ? elapsed : 1));
    printf("errors:         %" PRIu64 "\n", total_errors);
    printf("churn cycles:   %" PRIu64 "\n", churn_cycles);
    printf("samples dumped: %" PRIu64 " in %s\n", samples_dumped, sample_dir);
    printf("rss start:      %ld kB\n", rss_start);
    printf("rss end:        %ld kB  (Δ %+ld kB)\n", rss_end, rss_end - rss_start);
    printf("rss peak:       %ld kB  (Δ %+ld kB)\n", rss_peak, rss_peak - rss_start);
    printf("\nanalyze samples with:\n");
    printf("  cat %s/sample-*.bin | ent\n", sample_dir);
    printf("  cat %s/sample-*.bin | rngtest\n", sample_dir);
    printf("  dieharder -f <(cat %s/sample-*.bin) -g 201 -a\n", sample_dir);

    return (total_errors == 0) ? 0 : 1;
}
