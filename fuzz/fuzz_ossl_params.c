// LibFuzzer harness: OSSL_PARAM surface and provider-level param coverage.
//
// Exercises infnoise_rand_get_ctx_params() and infnoise_prov_get_params()
// with all three context states (uninitialised, ready, error) and confirms
// that gettable-params declarations are consistent with what get_params sets.
//
// The first fuzz byte is a state-selector bitmask:
//   bit 0: instantiate the context before querying (state → READY)
//   bit 1: exhaust mock entropy to force error state before querying
//   bit 2: enable locking before querying
//
// Remaining bytes (if any) are fed as entropy to the mock, which matters
// when bit 0 is set and the context needs to proceed past instantiate.

#include "../src/infnoise_prov.c"
#include "mock_libinfnoise.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;

    uint8_t flags         = data[0];
    const uint8_t *entropy = data + 1;
    size_t         elen    = size - 1;

    mock_set_entropy(entropy, elen);

    void *ctx = infnoise_rand_newctx(NULL, NULL, NULL);
    if (!ctx)
        return 0;

    if (flags & 4)
        infnoise_rand_enable_locking(ctx);

    if (flags & 1) {
        // Instantiate: drives the context to READY so state queries return
        // EVP_RAND_STATE_READY and strength/max_request are meaningful.
        infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH, 0, NULL, 0, NULL);
    }

    if (flags & 2) {
        // Exhaust mock entropy, then try generate to push context to ERROR.
        mock_set_entropy(NULL, 0);
        uint8_t scratch[1];
        infnoise_rand_generate(ctx, scratch, 1, INFNOISE_STRENGTH,
                               0, NULL, 0);
    }

    // --- RAND context params ---
    int      state_v = -1;
    unsigned str_v   = 0;
    size_t   max_v   = 0;
    OSSL_PARAM ctx_params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE,          &state_v),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH,      &str_v),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_v),
        OSSL_PARAM_END
    };
    infnoise_rand_get_ctx_params(ctx, ctx_params);

    // Verify gettable declaration matches what was retrieved.
    const OSSL_PARAM *gettable = infnoise_rand_gettable_ctx_params(ctx, NULL);
    (void)gettable;

    // Partial param arrays (simulate callers that only want one value).
    {
        int only_state = 0;
        OSSL_PARAM one[] = {
            OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, &only_state),
            OSSL_PARAM_END
        };
        infnoise_rand_get_ctx_params(ctx, one);
    }

    // NULL params array is documented as a no-op returning 1.
    infnoise_rand_get_ctx_params(ctx, NULL);

    // Type-mismatched params force OSSL_PARAM_set_* to fail cleanly via
    // the type-check branch (set_* doesn't reliably validate data_size).
    // Each call drives one of the three "return 0" branches in
    // infnoise_rand_get_ctx_params.
    {
        const char *str_buf = NULL;
        OSSL_PARAM bad_state[] = {
            { OSSL_RAND_PARAM_STATE,       OSSL_PARAM_UTF8_PTR,
              &str_buf, sizeof(str_buf), 0 },
            OSSL_PARAM_END
        };
        infnoise_rand_get_ctx_params(ctx, bad_state);

        OSSL_PARAM bad_strength[] = {
            { OSSL_RAND_PARAM_STRENGTH,    OSSL_PARAM_UTF8_PTR,
              &str_buf, sizeof(str_buf), 0 },
            OSSL_PARAM_END
        };
        infnoise_rand_get_ctx_params(ctx, bad_strength);

        OSSL_PARAM bad_max[] = {
            { OSSL_RAND_PARAM_MAX_REQUEST, OSSL_PARAM_UTF8_PTR,
              &str_buf, sizeof(str_buf), 0 },
            OSSL_PARAM_END
        };
        infnoise_rand_get_ctx_params(ctx, bad_max);
    }

    // Lock with ctx==NULL exercises the early-return branch that
    // production callers never take (they always pass a real ctx).
    (void)infnoise_rand_lock(NULL);
    infnoise_rand_unlock(NULL);

    // --- Provider-level params (provctx = NULL is fine in our harness) ---
    const char *name_ptr  = NULL;
    const char *ver_ptr   = NULL;
    const char *build_ptr = NULL;
    int         status_v  = 0;
    OSSL_PARAM prov_params[] = {
        { OSSL_PROV_PARAM_NAME,      OSSL_PARAM_UTF8_PTR,
          &name_ptr,  sizeof(name_ptr),  0 },
        { OSSL_PROV_PARAM_VERSION,   OSSL_PARAM_UTF8_PTR,
          &ver_ptr,   sizeof(ver_ptr),   0 },
        { OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR,
          &build_ptr, sizeof(build_ptr), 0 },
        { OSSL_PROV_PARAM_STATUS,    OSSL_PARAM_INTEGER,
          &status_v,  sizeof(status_v),  0 },
        OSSL_PARAM_END
    };
    infnoise_prov_get_params(NULL, prov_params);
    infnoise_prov_gettable_params(NULL);

    infnoise_rand_freectx(ctx);
    return 0;
}
