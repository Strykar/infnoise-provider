// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// TSan stress test - concurrent access to PROV_INFNOISE.
//
// Built with -fsanitize=thread; uses the mock libinfnoise stub so no USB
// device is needed.  Runs two scenarios:
//
//   1. Shared-context contention.  All threads share one EVP_RAND_CTX
//      instance and serialise via the provider's CRYPTO_RWLOCK around
//      every generate() call.  TSan must report no data races on
//      ctx->state / ctx->spill / ctx->trng_context.
//
//   2. Per-thread contexts.  Each thread allocates its own context and
//      runs the full lifecycle independently.  Verifies the provider
//      has no shared global state we missed (the unpatched libinfnoise
//      had global Keccak state; the patched fork is per-context, but
//      the provider itself must also remain context-isolated).
//
// Run: `make test-tsan` (separate target - TSan and libFuzzer don't
// compose, so this is its own binary, not a fuzz harness extension).

#include "../src/infnoise_prov.c"
#include "../fuzz/mock_libinfnoise.h"

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NUM_THREADS         4
#define ITERS_SHARED    20000
#define ITERS_PER_THR   20000
#define ENTROPY_SIZE  (4 << 20)   // 4 MiB

static uint8_t g_entropy[ENTROPY_SIZE];

// Sentinel pointer used as a worker thread's failure return value.
// Avoids casting integer literals to pointer (intToPointerCast).
static char         g_worker_failed_marker;
#define WORKER_FAILED ((void *)&g_worker_failed_marker)

// ---------------------------------------------------------------------------
// Scenario 1: shared context, locked generate.
// ---------------------------------------------------------------------------

static void *shared_worker(void *arg)
{
    void   *ctx = arg;
    uint8_t buf[64];

    for (int i = 0; i < ITERS_SHARED; i++) {
        if (!infnoise_rand_lock(ctx)) {
            fprintf(stderr, "shared_worker: lock failed\n");
            return WORKER_FAILED;
        }
        if (!infnoise_rand_generate(ctx, buf, 32, INFNOISE_STRENGTH,
                                    0, NULL, 0)) {
            infnoise_rand_unlock(ctx);
            fprintf(stderr, "shared_worker: generate failed at i=%d\n", i);
            return WORKER_FAILED;
        }
        infnoise_rand_unlock(ctx);
    }
    return NULL;
}

static int run_shared_scenario(void)
{
    mock_set_entropy(g_entropy, sizeof(g_entropy));

    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (!ctx) { fprintf(stderr, "newctx failed\n"); return 1; }
    if (!infnoise_rand_enable_locking(ctx)) {
        fprintf(stderr, "enable_locking failed\n");
        infnoise_rand_freectx(ctx);
        return 1;
    }
    if (!infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH,
                                   0, NULL, 0, NULL)) {
        fprintf(stderr, "instantiate failed\n");
        infnoise_rand_freectx(ctx);
        return 1;
    }

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, shared_worker, ctx) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    int rc = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        void *thread_rc;
        pthread_join(threads[i], &thread_rc);
        if (thread_rc != NULL) rc = 1;
    }

    infnoise_rand_uninstantiate(ctx);
    infnoise_rand_freectx(ctx);

    if (rc == 0) {
        printf("scenario 1 (shared ctx): %d threads x %d iters = %d generates OK\n",
               NUM_THREADS, ITERS_SHARED, NUM_THREADS * ITERS_SHARED);
    }
    return rc;
}

// ---------------------------------------------------------------------------
// Scenario 2: per-thread contexts, no provider locking needed.
// ---------------------------------------------------------------------------

static void *isolated_worker(void *arg)
{
    (void)arg;
    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (!ctx) return WORKER_FAILED;
    if (!infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH,
                                   0, NULL, 0, NULL)) {
        infnoise_rand_freectx(ctx);
        return WORKER_FAILED;
    }

    uint8_t buf[64];
    for (int i = 0; i < ITERS_PER_THR; i++) {
        if (!infnoise_rand_generate(ctx, buf, 32, INFNOISE_STRENGTH,
                                    0, NULL, 0)) {
            infnoise_rand_uninstantiate(ctx);
            infnoise_rand_freectx(ctx);
            return WORKER_FAILED;
        }
    }
    infnoise_rand_uninstantiate(ctx);
    infnoise_rand_freectx(ctx);
    return NULL;
}

static int run_isolated_scenario(void)
{
    // Refill mock entropy so per-thread generates have bytes available.
    // The mock serialises readData internally so no races on g_entropy_pos.
    mock_set_entropy(g_entropy, sizeof(g_entropy));

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, isolated_worker, NULL) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    int rc = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        void *thread_rc;
        pthread_join(threads[i], &thread_rc);
        if (thread_rc != NULL) rc = 1;
    }
    if (rc == 0) {
        printf("scenario 2 (per-thread ctxs): %d threads x %d iters = %d generates OK\n",
               NUM_THREADS, ITERS_PER_THR, NUM_THREADS * ITERS_PER_THR);
    }
    return rc;
}

int main(void)
{
    // Deterministic entropy pattern.
    for (size_t i = 0; i < sizeof(g_entropy); i++)
        g_entropy[i] = (uint8_t)((i * 7 + 13) & 0xFF);

    if (run_shared_scenario()) {
        fprintf(stderr, "scenario 1 FAILED\n");
        return 1;
    }
    if (run_isolated_scenario()) {
        fprintf(stderr, "scenario 2 FAILED\n");
        return 1;
    }

    printf("all TSan scenarios passed (no data races detected)\n");
    return 0;
}
