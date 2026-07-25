// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// Hardware stub that replaces libinfnoise at link time during fuzz builds.
//
// initInfnoise() succeeds by default; failure can be injected via
// mock_set_init_failure() to exercise the provider's error path.
//
// readData() draws from a fuzzer-seeded byte buffer so the provider's three-
// phase spill buffer logic (drain / direct / tail) is fully exercisable
// without physical hardware.  Three operating modes layered on top:
//
//   - Default ("friendly"):    return as much entropy as available, capped
//                              at MOCK_BATCH_SIZE per call.
//   - Scripted (set via
//     mock_set_chunk_script):  each call consumes one byte from a script;
//                              the byte modulo (MOCK_BATCH_SIZE + 1) becomes
//                              the return size, so 0 is an explicit transient
//                              and 1..63 are short reads.
//   - Fatal-after-N (set via
//     mock_set_fatal_after):   the N-th call returns INFNOISE_ERR_USB_READ
//                              (the patched libinfnoise's negative-rc path);
//                              subsequent calls return 0 transient.
//
// The patched libinfnoise.h is required by the provider (guarded with
// #ifndef INFNOISE_KECCAK_STATE_SIZE / #error in src/infnoise_prov.c),
// so readData() returns signed int32_t — < 0 fatal, 0 transient, > 0 OK.

#include <libinfnoise.h>
#include <pthread.h>
#include <string.h>

#define MOCK_BATCH_SIZE 64u

static const uint8_t *g_entropy;
static size_t         g_entropy_len;
static size_t         g_entropy_pos;

static const uint8_t *g_chunks;
static size_t         g_chunks_len;
static size_t         g_chunks_pos;

static int      g_fail_init;
static uint32_t g_fatal_after;
static uint32_t g_call_count;

// readData is called from worker threads in the TSan stress test, so the
// mock's globals (entropy_pos, chunks_pos, call_count) must be protected.
// Single-threaded fuzz harnesses pay an uncontested lock per call -
// negligible vs the rest of the work.  mock_set_* are called only from the
// caller's main thread before/after worker sections, so pthread_create's
// happens-before makes them visible without explicit locking.
static pthread_mutex_t g_mock_lock = PTHREAD_MUTEX_INITIALIZER;

void mock_set_entropy(const uint8_t *data, size_t len)
{
    g_entropy     = data;
    g_entropy_len = len;
    g_entropy_pos = 0;
}

void mock_set_chunk_script(const uint8_t *data, size_t len)
{
    g_chunks     = data;
    g_chunks_len = len;
    g_chunks_pos = 0;
}

void mock_set_init_failure(int fail_init)
{
    g_fail_init = fail_init;
}

void mock_set_fatal_after(uint32_t n)
{
    g_fatal_after = n;
    g_call_count  = 0;
}

bool initInfnoise(struct infnoise_context *ctx, char *serial,
                  bool keccak, bool debug)
{
    (void)serial; (void)keccak; (void)debug;
    if (g_fail_init) {
        ctx->message = "mock: injected init failure";
        return false;
    }
    ctx->message = NULL;
    return true;
}

void deinitInfnoise(struct infnoise_context *ctx)
{
    (void)ctx;
}

int32_t readData(struct infnoise_context *ctx, uint8_t *result,
                 bool raw, uint32_t outputMultiplier)
{
    (void)raw; (void)outputMultiplier;

    pthread_mutex_lock(&g_mock_lock);

    g_call_count++;
    if (g_fatal_after != 0 && g_call_count == g_fatal_after) {
        ctx->message = "mock: injected fatal error";
        pthread_mutex_unlock(&g_mock_lock);
        return INFNOISE_ERR_USB_READ;  // negative -> provider hits fatal path
    }

    uint32_t want;
    if (g_chunks != NULL) {
        if (g_chunks_pos >= g_chunks_len) {
            pthread_mutex_unlock(&g_mock_lock);
            return 0;
        }
        want = (uint32_t)g_chunks[g_chunks_pos++] % (MOCK_BATCH_SIZE + 1);
        if (want == 0) {
            pthread_mutex_unlock(&g_mock_lock);
            return 0;
        }
    } else {
        want = MOCK_BATCH_SIZE;
    }

    if (g_entropy == NULL || g_entropy_pos >= g_entropy_len) {
        pthread_mutex_unlock(&g_mock_lock);
        return 0;
    }

    size_t avail = g_entropy_len - g_entropy_pos;
    if (want > avail) want = (uint32_t)avail;
    if (want == 0) {
        pthread_mutex_unlock(&g_mock_lock);
        return 0;
    }

    memcpy(result, g_entropy + g_entropy_pos, want);
    g_entropy_pos += want;

    pthread_mutex_unlock(&g_mock_lock);
    return (int32_t)want;
}
