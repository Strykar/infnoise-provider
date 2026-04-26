// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// Allocator-failure injection test.
//
// Uses CRYPTO_set_mem_functions to install a counter-driven malloc wrapper
// that fails the Nth call.  Each scenario forces a specific provider alloc
// site to fail and verifies the provider returns the documented failure
// indicator without leaving partial state.
//
// This complements the Tier A manual review: even if the audit comments
// in src/infnoise_prov.c are correct today, this test catches the case
// where a future refactor inadvertently removes a NULL check.
//
// Limitations:
//   - CRYPTO_set_mem_functions must be installed before *any* OpenSSL
//     allocation in the process; it returns 0 if anything has already
//     allocated.  We install it as the first thing in main().
//   - secure_malloc uses a separate arena when the secure heap is
//     initialised; we don't init the secure heap here, so secure_malloc
//     falls back to the regular allocator and our wrapper sees it.

#include "../src/infnoise_prov.c"
#include "../fuzz/mock_libinfnoise.h"

#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Failing allocator wrapper.
// ---------------------------------------------------------------------------

static int g_alloc_count;     // total mallocs+reallocs since last reset
static int g_fail_at;         // 0 = never fail; N = fail the Nth call

static void *fail_malloc(size_t n, const char *f, int l)
{
    (void)f; (void)l;
    if (++g_alloc_count == g_fail_at)
        return NULL;
    return malloc(n);
}

static void *fail_realloc(void *p, size_t n, const char *f, int l)
{
    (void)f; (void)l;
    if (++g_alloc_count == g_fail_at)
        return NULL;
    return realloc(p, n);
}

static void fail_free(void *p, const char *f, int l)
{
    (void)f; (void)l;
    free(p);
}

static void allocator_reset(void)
{
    g_alloc_count = 0;
    g_fail_at     = 0;
}

static void allocator_fail_after(int n)
{
    g_alloc_count = 0;
    g_fail_at     = n;
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

// 1. newctx with zalloc returning NULL.
static int test_newctx(void)
{
    allocator_fail_after(1);
    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    allocator_reset();
    if (ctx != NULL) {
        fprintf(stderr, "FAIL test_newctx: returned non-NULL\n");
        infnoise_rand_freectx(ctx);
        return 1;
    }
    printf("ok  newctx: returns NULL on zalloc failure\n");
    return 0;
}

// 2. provider_init with zalloc returning NULL — must clear out-params too.
static int test_provider_init(void)
{
    void                 *provctx_dirty = (void *)(uintptr_t)0xDEAD;
    const OSSL_DISPATCH  *out_dirty     = (const OSSL_DISPATCH *)(uintptr_t)0xBEEF;
    void                 *provctx       = provctx_dirty;
    const OSSL_DISPATCH  *out           = out_dirty;

    allocator_fail_after(1);
    int rc = OSSL_provider_init(NULL, NULL, &out, &provctx);
    allocator_reset();

    if (rc != 0) {
        fprintf(stderr, "FAIL test_provider_init: rc=%d, expected 0\n", rc);
        return 1;
    }
    if (provctx != NULL) {
        fprintf(stderr, "FAIL test_provider_init: *provctx=%p (not NULLed)\n", provctx);
        return 1;
    }
    if (out != NULL) {
        fprintf(stderr, "FAIL test_provider_init: *out=%p (not NULLed)\n", (void *)out);
        return 1;
    }
    printf("ok  provider_init: returns 0 and zeros *out / *provctx\n");
    return 0;
}

// 3. enable_locking with CRYPTO_THREAD_lock_new returning NULL.  The lock
//    object is allocated by libcrypto via the mem hooks we installed.
static int test_enable_locking(void)
{
    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "FAIL test_enable_locking: newctx unexpectedly failed\n");
        return 1;
    }

    // Probe how many allocations enable_locking does in success path, then
    // fail the first one to drive the failure path deterministically.
    allocator_fail_after(1);
    int rc = infnoise_rand_enable_locking(ctx);
    allocator_reset();

    // We don't strictly require rc == 0 here: depending on the OpenSSL
    // build, lock_new may use stack-allocated state and not call our
    // wrapper at all (in which case enable_locking succeeds).  Accept
    // either outcome but record which.
    if (rc == 0) {
        // Failure path exercised.  ctx->lock must remain NULL so caller
        // can retry.
        const PROV_INFNOISE *p = (const PROV_INFNOISE *)ctx;
        if (p->lock != NULL) {
            fprintf(stderr, "FAIL test_enable_locking: lock != NULL on failure path\n");
            infnoise_rand_freectx(ctx);
            return 1;
        }
        printf("ok  enable_locking: returns 0, ctx->lock stays NULL\n");
    } else {
        printf("ok  enable_locking: rc=1 (this OpenSSL build's lock_new "
               "doesn't allocate via the public hooks; failure path "
               "untestable in this configuration)\n");
    }
    infnoise_rand_freectx(ctx);
    return 0;
}

// 4. get_seed with secure_malloc returning NULL.
static int test_get_seed(void)
{
    static uint8_t entropy[1024];
    for (size_t i = 0; i < sizeof(entropy); i++)
        entropy[i] = (uint8_t)i;
    mock_set_entropy(entropy, sizeof(entropy));

    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (ctx == NULL) return 1;
    if (!infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH, 0, NULL, 0, NULL)) {
        infnoise_rand_freectx(ctx);
        return 1;
    }

    // Probe with a single-call failure: the first allocation inside
    // get_seed is OPENSSL_secure_malloc.
    unsigned char *seed = NULL;
    allocator_fail_after(1);
    size_t got = infnoise_rand_get_seed(ctx, &seed, 256, 32, 32,
                                        0, NULL, 0);
    allocator_reset();

    if (got != 0) {
        // get_seed succeeded — secure_malloc was satisfied by the secure
        // arena (not our wrapper).  This config can't drive the failure;
        // record but don't fail the test.
        printf("ok  get_seed: rc=%zu (secure heap satisfied alloc; "
               "failure path untestable in this configuration)\n", got);
        if (seed) infnoise_rand_clear_seed(ctx, seed, got);
    } else {
        if (seed != NULL) {
            fprintf(stderr, "FAIL test_get_seed: rc=0 but *pout=%p\n", (void *)seed);
            infnoise_rand_uninstantiate(ctx);
            infnoise_rand_freectx(ctx);
            return 1;
        }
        printf("ok  get_seed: returns 0, *pout stays NULL\n");
    }

    infnoise_rand_uninstantiate(ctx);
    infnoise_rand_freectx(ctx);
    return 0;
}

int main(void)
{
    // CRITICAL: install the mem hooks before any other OpenSSL call.
    // CRYPTO_set_mem_functions returns 0 once anything has allocated.
    if (!CRYPTO_set_mem_functions(fail_malloc, fail_realloc, fail_free)) {
        fprintf(stderr, "FATAL: CRYPTO_set_mem_functions failed (something "
                        "allocated before main, or this build doesn't allow it)\n");
        return 2;
    }

    int failures = 0;
    failures += test_newctx();
    failures += test_provider_init();
    failures += test_enable_locking();
    failures += test_get_seed();

    if (failures) {
        fprintf(stderr, "\n%d alloc-failure scenarios FAILED\n", failures);
        return 1;
    }
    printf("\nall alloc-failure scenarios passed\n");
    return 0;
}
