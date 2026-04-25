// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// OpenSSL 3.x Provider implementing OSSL_OP_RAND using the Infinite Noise TRNG
// to generate true random numbers: https://github.com/waywardgeek/infnoise
//
// Written from scratch for the Provider API (OpenSSL 3.x).
// Reference implementations studied:
//   - OpenSSL providers/implementations/rands/seed_src_jitter.c
//   - OpenSSL providers/implementations/rands/seed_src.c
//   - OpenSSL providers/implementations/rands/test_rng.c
//   - latchset/pkcs11-provider src/random.c
//   - provider-corner/vigenere vigenere.c

#include <libinfnoise.h>

// This provider requires the patched libinfnoise fork: per-context Keccak and
// health-check state (no globals), and signed int32_t readData() return value
// (< 0 fatal, 0 transient, > 0 bytes).  The marker is INFNOISE_KECCAK_STATE_SIZE
// which the patched header defines and the upstream waywardgeek/infnoise does
// not.  Building against unpatched libinfnoise is unsupported (global state
// breaks multi-context use; exit() on health failure breaks error recovery).
#ifndef INFNOISE_KECCAK_STATE_SIZE
#  error "libinfnoise must be the patched fork (INFNOISE_KECCAK_STATE_SIZE undefined)"
#endif

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/randerr.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

///////////////////
// Configuration
///////////////////

#define INFNOISE_PROV_VERSION "1.5.0"
#define INFNOISE_PROV_BUILDINFO "infnoise-provider " INFNOISE_PROV_VERSION

// Output multiplier for the Keccak sponge.  With multiplier=2, each USB
// round-trip yields 64 bytes (512 bits squeezed from the 1600-bit Keccak
// state after absorbing 512 raw bits).  This doubles throughput (~50 KB/s
// vs ~25 KB/s) with no loss in security: the sponge retains 1088 bits of
// hidden capacity, well above our 256-bit strength claim.
static const int kInfnoiseMultiplier = 2;
static const char *kInfnoiseSerial = NULL;
static const bool kKeccak = true;
static const bool kDebug = false;

// Keccak-processed output from the Infinite Noise TRNG provides
// full entropy: 8 bits per byte.  We claim 256 bits of security
// strength, matching the Keccak sponge width.
#define INFNOISE_STRENGTH 256u

// Cap per-call generate size.  The device runs at ~40 KB/s over USB;
// INT_MAX would block for days.  1 MiB is generous for any single
// cryptographic operation and prevents accidental denial of service.
#define INFNOISE_MAX_REQUEST ((size_t)(1024 * 1024))

// Maximum consecutive zero-byte readData returns before we declare
// the device dead.  100 iterations at USB latency is well under 1s.
#define INFNOISE_MAX_ZERO_READS 100

////////////////////////////////
// Spill buffer implementation
////////////////////////////////

// readData returns a fixed number of bytes per USB round-trip, determined
// by the Keccak multiplier.  With multiplier=2: 64 bytes per call.
// BUFLEN (512) is the USB buffer size, NOT the readData output size.
// BATCH_SIZE is the actual readData output size we must handle.
//
// libinfnoise (the patched fork required by this provider) holds Keccak and
// health-check state per-context, so multiple PROV_INFNOISE contexts can
// coexist safely at the library level.  FTDI USB exclusion still limits
// open handles to one per physical device, and CRYPTO_RWLOCK serialises
// concurrent OpenSSL threads sharing a single context.
#define BATCH_SIZE 64u  // multiplier=2, keccak=true: 2*256/8 = 64

// When readData returns BATCH_SIZE bytes but the caller needs fewer,
// the leftover bytes are kept in a flat spill buffer.  For requests
// >= BATCH_SIZE we copy directly from readData to the caller, avoiding
// the intermediate buffer entirely.

typedef struct {
    uint8_t data[BATCH_SIZE];
    size_t offset;    // next byte to read
    size_t length;    // valid bytes in data[]
} SpillBuffer;

static void SpillBufferInit(SpillBuffer *sb)
{
    OPENSSL_cleanse(sb, sizeof(*sb));
}

static size_t SpillBufferDrain(SpillBuffer *sb, uint8_t *out, size_t num_bytes)
{
    size_t avail = sb->length - sb->offset;
    if (avail == 0)
        return 0;

    size_t n = avail < num_bytes ? avail : num_bytes;
    memcpy(out, sb->data + sb->offset, n);
    OPENSSL_cleanse(sb->data + sb->offset, n);
    sb->offset += n;

    // When fully drained, reset to avoid stale state.
    if (sb->offset == sb->length) {
        sb->offset = 0;
        sb->length = 0;
    }
    return n;
}

static void SpillBufferStore(SpillBuffer *sb, const uint8_t *data,
                             size_t length)
{
    // Called only when the buffer is empty.
    memcpy(sb->data, data, length);
    sb->offset = 0;
    sb->length = length;
}

///////////////////////////
// RAND provider context
///////////////////////////

typedef struct {
    void *provctx;
    struct infnoise_context trng_context;
    SpillBuffer spill;
    int state;
    CRYPTO_RWLOCK *lock;
} PROV_INFNOISE;

//////////////////////////////
// RAND dispatch functions
//////////////////////////////

static OSSL_FUNC_rand_newctx_fn infnoise_rand_newctx;
static OSSL_FUNC_rand_freectx_fn infnoise_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn infnoise_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn infnoise_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn infnoise_rand_generate;
static OSSL_FUNC_rand_reseed_fn infnoise_rand_reseed;
static OSSL_FUNC_rand_gettable_ctx_params_fn infnoise_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn infnoise_rand_get_ctx_params;
static OSSL_FUNC_rand_enable_locking_fn infnoise_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn infnoise_rand_lock;
static OSSL_FUNC_rand_unlock_fn infnoise_rand_unlock;
static OSSL_FUNC_rand_get_seed_fn infnoise_rand_get_seed;
static OSSL_FUNC_rand_clear_seed_fn infnoise_rand_clear_seed;
static OSSL_FUNC_rand_verify_zeroization_fn infnoise_rand_verify_zeroization;

static void *infnoise_rand_newctx(void *provctx, void *parent,
                                   UNUSED const OSSL_DISPATCH *parent_dispatch)
{
    PROV_INFNOISE *ctx;

    // A hardware TRNG seed source must not have a parent.
    if (parent != NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;   // SECURITY: reviewed 2026-04-25 — no partial state.

    ctx->provctx = provctx;
    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    SpillBufferInit(&ctx->spill);
    return ctx;
}

static void infnoise_rand_freectx(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx == NULL)
        return;

    // Release the TRNG device if it was ever initialised — including
    // after errors, to avoid leaking the USB handle.
    if (ctx->state == EVP_RAND_STATE_READY
        || ctx->state == EVP_RAND_STATE_ERROR)
        deinitInfnoise(&ctx->trng_context);

    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int infnoise_rand_instantiate(void *vctx, unsigned int strength,
                                     UNUSED int prediction_resistance,
                                     UNUSED const unsigned char *pstr,
                                     UNUSED size_t pstr_len,
                                     UNUSED const OSSL_PARAM params[])
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (strength > INFNOISE_STRENGTH) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH,
                       "requested %u, device provides %u",
                       strength, INFNOISE_STRENGTH);
        return 0;
    }

    // Guard against double-instantiate without uninstantiate: the FTDI
    // context inside trng_context would leak.
    if (ctx->state == EVP_RAND_STATE_READY)
        deinitInfnoise(&ctx->trng_context);

    // libinfnoise takes char* (not const char*) for the serial parameter.
    if (!initInfnoise(&ctx->trng_context, (char *)(uintptr_t)kInfnoiseSerial,
                      kKeccak, kDebug)) {
        ERR_raise_data(ERR_LIB_RAND, RAND_R_ERROR_RETRIEVING_ENTROPY,
                       "initInfnoise: %s",
                       ctx->trng_context.message
                           ? ctx->trng_context.message
                           : "unknown");
        ctx->state = EVP_RAND_STATE_ERROR;
        return 0;
    }

    ctx->state = EVP_RAND_STATE_READY;
    return 1;
}

static int infnoise_rand_uninstantiate(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx->state == EVP_RAND_STATE_READY)
        deinitInfnoise(&ctx->trng_context);

    SpillBufferInit(&ctx->spill);
    OPENSSL_cleanse(&ctx->trng_context, sizeof(ctx->trng_context));

    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

// Read up to BATCH_SIZE bytes from the TRNG into buf.  Returns the
// number of bytes actually read, or 0 on hard failure (state set to
// ERROR).
static uint32_t infnoise_read_device(PROV_INFNOISE *ctx,
                                     uint8_t buf[BATCH_SIZE])
{
    int zero_reads = 0;

    for (;;) {
        // Patched libinfnoise: signed rc — < 0 fatal, 0 transient, > 0 bytes.
        // The fatal rc value itself is the infnoise_error_t code.
        int32_t rc = readData(&ctx->trng_context, buf,
                              !kKeccak, kInfnoiseMultiplier);

        if (rc < 0) {
            ERR_raise_data(ERR_LIB_RAND, RAND_R_ERROR_RETRIEVING_ENTROPY,
                           "readData: %s (code %d)",
                           ctx->trng_context.message
                               ? ctx->trng_context.message
                               : "unknown",
                           (int)rc);
            OPENSSL_cleanse(buf, BATCH_SIZE);
            ctx->state = EVP_RAND_STATE_ERROR;
            return 0;
        }

        if (rc > 0)
            return (uint32_t)rc;

        // readData returned 0: transient (timing or entropy off-target).
        if (++zero_reads >= INFNOISE_MAX_ZERO_READS) {
            ERR_raise_data(ERR_LIB_RAND, RAND_R_ERROR_RETRIEVING_ENTROPY,
                           "readData returned 0 bytes %d consecutive times",
                           INFNOISE_MAX_ZERO_READS);
            ctx->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
    }
}

static int infnoise_rand_generate(void *vctx, unsigned char *out,
                                  size_t outlen, unsigned int strength,
                                  UNUSED int prediction_resistance,
                                  UNUSED const unsigned char *addin,
                                  UNUSED size_t addin_len)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx->state != EVP_RAND_STATE_READY) {
        ERR_raise(ERR_LIB_PROV,
                  ctx->state == EVP_RAND_STATE_ERROR
                      ? PROV_R_IN_ERROR_STATE
                      : PROV_R_NOT_INSTANTIATED);
        return 0;
    }

    if (strength > INFNOISE_STRENGTH) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INSUFFICIENT_DRBG_STRENGTH,
                       "requested %u, device provides %u",
                       strength, INFNOISE_STRENGTH);
        return 0;
    }

    if (outlen > INFNOISE_MAX_REQUEST) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "requested %zu bytes exceeds max %zu",
                       outlen, INFNOISE_MAX_REQUEST);
        return 0;
    }

    // Zero-length request is trivially successful and must not touch out;
    // callers may legitimately pass out == NULL with outlen == 0, and any
    // pointer arithmetic on a null pointer (even +0) is undefined behaviour.
    if (outlen == 0)
        return 1;

    unsigned char *w_ptr = out;
    size_t remaining = outlen;

    // Phase 1: drain any leftover bytes from the previous call.
    size_t drained = SpillBufferDrain(&ctx->spill, w_ptr, remaining);
    w_ptr += drained;
    remaining -= drained;

    // Phase 2: for full batches, copy directly from the device to the
    // caller's buffer — no intermediate buffer, no extra memcpy.
    while (remaining >= BATCH_SIZE) {
        uint32_t n = infnoise_read_device(ctx, w_ptr);
        if (n == 0) {
            OPENSSL_cleanse(out, outlen);
            return 0;
        }
        w_ptr += n;
        remaining -= n;
    }

    // Phase 3: tail (< BATCH_SIZE).  Read until the request is satisfied,
    // looping on short reads — readData's contract guarantees only "> 0
    // bytes written," not BATCH_SIZE bytes.  When a read overshoots
    // remaining, the surplus goes to the spill buffer for the next call.
    while (remaining > 0) {
        uint8_t batch[BATCH_SIZE];
        uint32_t n = infnoise_read_device(ctx, batch);
        if (n == 0) {
            OPENSSL_cleanse(out, outlen);
            return 0;
        }

        size_t give = remaining < n ? remaining : n;
        memcpy(w_ptr, batch, give);
        w_ptr     += give;
        remaining -= give;

        if (give < n)
            SpillBufferStore(&ctx->spill, batch + give, n - give);

        OPENSSL_cleanse(batch, BATCH_SIZE);
    }

    return 1;
}

static int infnoise_rand_reseed(void *vctx, UNUSED int prediction_resistance,
                                UNUSED const unsigned char *ent,
                                UNUSED size_t ent_len,
                                UNUSED const unsigned char *addin,
                                UNUSED size_t addin_len)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx->state != EVP_RAND_STATE_READY) {
        ERR_raise(ERR_LIB_PROV,
                  ctx->state == EVP_RAND_STATE_ERROR
                      ? PROV_R_IN_ERROR_STATE
                      : PROV_R_NOT_INSTANTIATED);
        return 0;
    }
    // No-op: a TRNG is its own entropy source and cannot be reseeded.
    return 1;
}

static const OSSL_PARAM infnoise_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *infnoise_rand_gettable_ctx_params(UNUSED void *vctx,
                                                            UNUSED void *provctx)
{
    return infnoise_gettable_ctx_params;
}

static int infnoise_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->state))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, INFNOISE_STRENGTH))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, INFNOISE_MAX_REQUEST))
        return 0;

    return 1;
}

// Caller MUST check the return value before relying on subsequent lock()/
// unlock() to actually serialise: when this returns 0, lock() and unlock()
// become silent no-ops on the same context (the ctx->lock == NULL guards
// in those functions), so unsynchronised concurrent use would be a race.
static int infnoise_rand_enable_locking(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx != NULL && ctx->lock == NULL) {
        ctx->lock = CRYPTO_THREAD_lock_new();
        if (ctx->lock == NULL) {
            // SECURITY: reviewed 2026-04-25 — ctx->lock stays NULL,
            // caller can retry on next call without leak.
            ERR_raise(ERR_LIB_PROV, RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }
    return 1;
}

static int infnoise_rand_lock(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx == NULL || ctx->lock == NULL)
        return 1;
    return CRYPTO_THREAD_write_lock(ctx->lock);
}

static void infnoise_rand_unlock(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx != NULL && ctx->lock != NULL)
        CRYPTO_THREAD_unlock(ctx->lock);
}

static size_t infnoise_rand_get_seed(void *vctx, unsigned char **pout,
                                     UNUSED int entropy, size_t min_len,
                                     size_t max_len,
                                     int prediction_resistance,
                                     const unsigned char *adin,
                                     size_t adin_len)
{
    size_t len = min_len;

    // Respect the ceiling.
    if (max_len < len)
        len = max_len;

    if (len == 0)
        return 0;

    unsigned char *buf = OPENSSL_secure_malloc(len);
    if (buf == NULL)
        return 0;   // SECURITY: reviewed 2026-04-25 — *pout untouched.

    if (!infnoise_rand_generate(vctx, buf, len, 0, prediction_resistance,
                                adin, adin_len)) {
        OPENSSL_secure_clear_free(buf, len);
        return 0;
    }

    *pout = buf;
    return len;
}

static void infnoise_rand_clear_seed(UNUSED void *vctx, unsigned char *buf,
                                     size_t len)
{
    OPENSSL_secure_clear_free(buf, len);
}

static int infnoise_rand_verify_zeroization(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx == NULL)
        return 0;

    // When uninstantiated, the spill buffer and trng_context are cleansed.
    if (ctx->state != EVP_RAND_STATE_UNINITIALISED)
        return 0;

    // Use constant-time comparison against zero to prevent the compiler
    // from optimising away the check after OPENSSL_cleanse.
    unsigned char zero[sizeof(ctx->spill)];
    memset(zero, 0, sizeof(zero));
    if (CRYPTO_memcmp(&ctx->spill, zero, sizeof(zero)) != 0)
        return 0;

    return 1;
}

///////////////////////////
// RAND dispatch table
///////////////////////////

static const OSSL_DISPATCH infnoise_rand_dispatch[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))infnoise_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))infnoise_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))infnoise_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,
      (void (*)(void))infnoise_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))infnoise_rand_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))infnoise_rand_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,
      (void (*)(void))infnoise_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))infnoise_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))infnoise_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void (*)(void))infnoise_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,
      (void (*)(void))infnoise_rand_get_ctx_params },
    { OSSL_FUNC_RAND_GET_SEED, (void (*)(void))infnoise_rand_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))infnoise_rand_clear_seed },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
      (void (*)(void))infnoise_rand_verify_zeroization },
    { 0, NULL }  // OSSL_DISPATCH_END equivalent; portable across all 3.x
};

///////////////////////////
// Provider-level setup
///////////////////////////

static const OSSL_ALGORITHM infnoise_rands[] = {
    { "infnoise", "provider=infnoise", infnoise_rand_dispatch,
      "Infinite Noise TRNG" },
    { NULL, NULL, NULL, NULL }
};

static OSSL_FUNC_provider_query_operation_fn infnoise_prov_query;
static OSSL_FUNC_provider_gettable_params_fn infnoise_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn infnoise_prov_get_params;
static OSSL_FUNC_provider_teardown_fn infnoise_prov_teardown;

static const OSSL_ALGORITHM *infnoise_prov_query(UNUSED void *provctx,
                                                  int operation_id,
                                                  int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_RAND:
        return infnoise_rands;
    }
    return NULL;
}

static const OSSL_PARAM infnoise_prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *infnoise_prov_gettable_params(UNUSED void *provctx)
{
    return infnoise_prov_param_types;
}

static int infnoise_prov_get_params(UNUSED void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, "Infinite Noise TRNG Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, INFNOISE_PROV_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, INFNOISE_PROV_BUILDINFO))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

typedef struct {
    const OSSL_CORE_HANDLE *handle;
} INFNOISE_PROV_CTX;

static void infnoise_prov_teardown(void *vprovctx)
{
    OPENSSL_free(vprovctx);
}

static const OSSL_DISPATCH infnoise_prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))infnoise_prov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))infnoise_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))infnoise_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))infnoise_prov_query },
    { 0, NULL }  // OSSL_DISPATCH_END equivalent; portable across all 3.x
};

///////////////////////////
// Provider entry point
///////////////////////////

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       UNUSED const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    INFNOISE_PROV_CTX *ctx;

    // Defense-in-depth: clear caller's out parameters before any work, so a
    // misbehaving loader that ignores our return value can't deref garbage.
    *provctx = NULL;
    *out     = NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;   // SECURITY: reviewed 2026-04-25 — outs cleared above.

    ctx->handle = handle;
    *provctx = ctx;
    *out = infnoise_prov_dispatch;
    return 1;
}
