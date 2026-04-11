// Copyright 2018 Thomás Inskip. All rights reserved.
// Copyright 2025-2026 Avinash H. Duduskar. Provider API refactor.
// SPDX-License-Identifier: MIT
// https://github.com/Strykar/infnoise-openssl
//
// OpenSSL 3.x Provider implementing OSSL_OP_RAND using the Infinite Noise TRNG
// to generate true random numbers: https://github.com/13-37-org/infnoise
//
// Refactored from the deprecated ENGINE API to the Provider API.
// Reference implementations studied:
//   - OpenSSL providers/implementations/rands/seed_src_jitter.c
//   - OpenSSL providers/implementations/rands/seed_src.c
//   - OpenSSL providers/implementations/rands/test_rng.c
//   - latchset/pkcs11-provider src/random.c
//   - provider-corner/vigenere vigenere.c

#include <libinfnoise.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/randerr.h>
#include <openssl/crypto.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

///////////////////
// Configuration
///////////////////

static const int kInfnoiseMultiplier = 1;
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

////////////////////////////////
// Ring buffer implementation
////////////////////////////////

// Sized to hold two TRNG read batches so we do not waste TRNG bytes.
#define RING_BUFFER_SIZE (2u * BUFLEN)

typedef struct {
    uint8_t buffer[RING_BUFFER_SIZE];
    size_t r_idx;
    size_t w_idx;
    size_t bytes_in_buffer;
} RingBuffer;

static void RingBufferInit(RingBuffer *rb)
{
    OPENSSL_cleanse(rb, sizeof(*rb));
}

static size_t RingBufferRead(RingBuffer *rb, size_t num_bytes,
                             uint8_t *output)
{
    if (rb->bytes_in_buffer == 0)
        return 0;

    size_t total_bytes_read = 0;

    if (rb->r_idx >= rb->w_idx) {
        size_t bytes_in_front = sizeof(rb->buffer) - rb->r_idx;
        size_t bytes_read = MIN(num_bytes, bytes_in_front);
        memcpy(output, rb->buffer + rb->r_idx, bytes_read);
        OPENSSL_cleanse(rb->buffer + rb->r_idx, bytes_read);
        rb->r_idx += bytes_read;
        if (rb->r_idx == sizeof(rb->buffer))
            rb->r_idx = 0;
        rb->bytes_in_buffer -= bytes_read;
        total_bytes_read += bytes_read;
        num_bytes -= bytes_read;
    }

    if (num_bytes > 0) {
        size_t bytes_read = MIN(num_bytes, rb->bytes_in_buffer);
        memcpy(output + total_bytes_read, rb->buffer + rb->r_idx,
               bytes_read);
        OPENSSL_cleanse(rb->buffer + rb->r_idx, bytes_read);
        rb->r_idx += bytes_read;
        if (rb->r_idx == sizeof(rb->buffer))
            rb->r_idx = 0;
        rb->bytes_in_buffer -= bytes_read;
        total_bytes_read += bytes_read;
    }

    return total_bytes_read;
}

static size_t RingBufferWrite(RingBuffer *rb, size_t num_bytes,
                              const uint8_t *input)
{
    if (sizeof(rb->buffer) - rb->bytes_in_buffer == 0)
        return 0;

    size_t total_bytes_written = 0;

    if (rb->w_idx >= rb->r_idx) {
        size_t free_bytes_in_front = sizeof(rb->buffer) - rb->w_idx;
        size_t bytes_write = MIN(num_bytes, free_bytes_in_front);
        memcpy(rb->buffer + rb->w_idx, input, bytes_write);
        rb->w_idx += bytes_write;
        if (rb->w_idx == sizeof(rb->buffer))
            rb->w_idx = 0;
        rb->bytes_in_buffer += bytes_write;
        total_bytes_written += bytes_write;
        num_bytes -= bytes_write;
    }

    if (num_bytes > 0) {
        size_t bytes_write =
            MIN(num_bytes, sizeof(rb->buffer) - rb->bytes_in_buffer);
        memcpy(rb->buffer + rb->w_idx, input + total_bytes_written,
               bytes_write);
        rb->w_idx += bytes_write;
        if (rb->w_idx == sizeof(rb->buffer))
            rb->w_idx = 0;
        rb->bytes_in_buffer += bytes_write;
        total_bytes_written += bytes_write;
    }

    return total_bytes_written;
}

///////////////////////////
// RAND provider context
///////////////////////////

typedef struct {
    void *provctx;
    struct infnoise_context trng_context;
    RingBuffer ring_buffer;
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
        return NULL;

    ctx->provctx = provctx;
    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    RingBufferInit(&ctx->ring_buffer);
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

    OPENSSL_cleanse(&ctx->ring_buffer, sizeof(ctx->ring_buffer));
    RingBufferInit(&ctx->ring_buffer);
    OPENSSL_cleanse(&ctx->trng_context, sizeof(ctx->trng_context));

    ctx->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
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
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "requested %zu bytes, max %zu",
                       outlen, INFNOISE_MAX_REQUEST);
        return 0;
    }

    // readData() can transiently return 0 bytes (USB timing).
    // Retry up to this many consecutive zero-byte reads before giving up.
    static const int kMaxZeroReads = 100;

    unsigned char *w_ptr = out;
    size_t remaining = outlen;
    int zero_reads = 0;

    while (remaining > 0) {
        size_t bytes_read = RingBufferRead(&ctx->ring_buffer, remaining,
                                           w_ptr);
        w_ptr += bytes_read;
        remaining -= bytes_read;

        if (remaining > 0) {
            uint8_t rand_buffer[BUFLEN];
            uint32_t rand_bytes = readData(&ctx->trng_context, rand_buffer,
                                           !kKeccak, kInfnoiseMultiplier);

            if (ctx->trng_context.errorFlag) {
                ERR_raise_data(ERR_LIB_RAND, RAND_R_ERROR_RETRIEVING_ENTROPY,
                               "readData: %s",
                               ctx->trng_context.message
                                   ? ctx->trng_context.message
                                   : "unknown");
                OPENSSL_cleanse(rand_buffer, sizeof(rand_buffer));
                OPENSSL_cleanse(out, outlen);
                ctx->state = EVP_RAND_STATE_ERROR;
                return 0;
            }

            if (rand_bytes == 0) {
                if (++zero_reads >= kMaxZeroReads) {
                    ERR_raise_data(ERR_LIB_RAND,
                                   RAND_R_ERROR_RETRIEVING_ENTROPY,
                                   "readData returned 0 bytes %d times",
                                   kMaxZeroReads);
                    OPENSSL_cleanse(out, outlen);
                    ctx->state = EVP_RAND_STATE_ERROR;
                    return 0;
                }
                continue;
            }
            zero_reads = 0;

            size_t bytes_written = RingBufferWrite(&ctx->ring_buffer,
                                                   rand_bytes, rand_buffer);
            OPENSSL_cleanse(rand_buffer, sizeof(rand_buffer));

            if (bytes_written != rand_bytes) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                OPENSSL_cleanse(out, outlen);
                ctx->state = EVP_RAND_STATE_ERROR;
                return 0;
            }
        }
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

static int infnoise_rand_enable_locking(void *vctx)
{
    PROV_INFNOISE *ctx = (PROV_INFNOISE *)vctx;

    if (ctx != NULL && ctx->lock == NULL) {
        ctx->lock = CRYPTO_THREAD_lock_new();
        if (ctx->lock == NULL) {
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
        return 0;

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

    // When uninstantiated, the ring buffer and trng_context are cleansed.
    // Verify the ring buffer is actually zeroed.
    if (ctx->state != EVP_RAND_STATE_UNINITIALISED)
        return 0;

    const unsigned char *p = (const unsigned char *)&ctx->ring_buffer;
    for (size_t i = 0; i < sizeof(ctx->ring_buffer); i++) {
        if (p[i] != 0)
            return 0;
    }
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
    OSSL_DISPATCH_END
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
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.1.0"))
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
    OSSL_DISPATCH_END
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

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    *provctx = ctx;
    *out = infnoise_prov_dispatch;
    return 1;
}
