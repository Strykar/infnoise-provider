// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// LibFuzzer harness: boundary and spill-buffer coverage.
//
// Input layout (all little-endian):
//   [u32] strength   — fed to instantiate and generate; > 256 must be rejected
//   [u32] outlen     — generate request size; > 1 MiB must be rejected
//   [u32] addin_len  — capped to remaining bytes after header
//   [addin_len bytes] additional input (passed but ignored by provider)
//   [rest] entropy   — consumed by mock readData(), exercises all spill phases
//
// Returns -1 for inputs too small to be useful (libFuzzer won't add these
// to the corpus, encouraging the fuzzer to grow toward interesting sizes).

#include "../src/infnoise_prov.c"
#include "mock_libinfnoise.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HDR_SIZE 12u  // 3 × uint32_t

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < HDR_SIZE)
        return -1;

    uint32_t strength, outlen, addin_len;
    memcpy(&strength,  data,     4);
    memcpy(&outlen,    data + 4, 4);
    memcpy(&addin_len, data + 8, 4);

    size_t avail = size - HDR_SIZE;
    if (addin_len > (uint32_t)avail)
        addin_len = (uint32_t)avail;

    const uint8_t *addin      = data + HDR_SIZE;
    const uint8_t *entropy    = data + HDR_SIZE + addin_len;
    size_t         entropy_sz = size - HDR_SIZE - addin_len;

    mock_set_entropy(entropy, entropy_sz);

    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (!ctx)
        return 0;

    if (!infnoise_rand_instantiate(ctx, strength, 0, NULL, 0, NULL))
        goto teardown;

    // generate: provider must reject outlen > INFNOISE_MAX_REQUEST and
    // strength > INFNOISE_STRENGTH before touching the output buffer.
    {
        size_t safe = (outlen <= INFNOISE_MAX_REQUEST) ? outlen : 0;
        uint8_t *out = safe > 0 ? malloc(safe) : NULL;
        if (safe == 0 || out) {
            infnoise_rand_generate(ctx, out, outlen, strength, 0,
                                   addin, addin_len);
        }
        free(out);
    }

    // get_seed exercises the secure-malloc path and calls generate internally.
    {
        unsigned char *seed = NULL;
        size_t seed_sz = (outlen <= 4096) ? outlen : 0;
        if (seed_sz > 0) {
            mock_set_entropy(entropy, entropy_sz);
            size_t got = infnoise_rand_get_seed(ctx, &seed, 256,
                                                seed_sz, seed_sz,
                                                0, addin, addin_len);
            if (seed)
                infnoise_rand_clear_seed(ctx, seed, got);
        }
    }

    // get_ctx_params: reads state, strength, max_request from the context.
    {
        int      state_v = 0;
        unsigned str_v   = 0;
        size_t   max_v   = 0;
        OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_RAND_PARAM_STATE,       &state_v),
            OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH,   &str_v),
            OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_v),
            OSSL_PARAM_END
        };
        infnoise_rand_get_ctx_params(ctx, params);
    }

    infnoise_rand_uninstantiate(ctx);
    infnoise_rand_verify_zeroization(ctx);

teardown:
    infnoise_rand_freectx(ctx);
    return 0;
}
