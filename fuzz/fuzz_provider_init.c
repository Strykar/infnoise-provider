// LibFuzzer harness: provider-level entry points.
//
// Covers OSSL_provider_init, infnoise_prov_query, infnoise_prov_teardown,
// infnoise_prov_get_params, and infnoise_prov_gettable_params - the
// functions OpenSSL itself calls when loading the provider via
// OSSL_PROVIDER_load().  None of the EVP_RAND-driven harnesses reach
// these paths; they need a direct invocation.
//
// The fuzzer's input is mostly used to perturb the params arrays (key
// sets, return-buffer sizes, type mismatches) once init is wired up.

#include "../src/infnoise_prov.c"
#include "mock_libinfnoise.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    uint8_t flags = data[0];

    // 1. Initialise the provider.  handle is opaque to us; the provider
    //    only stashes it in the context.
    void                  *provctx  = NULL;
    const OSSL_DISPATCH   *out_disp = NULL;
    if (OSSL_provider_init((const OSSL_CORE_HANDLE *)(uintptr_t)0xCAFE,
                           NULL, &out_disp, &provctx) != 1)
        return 0;

    // 2. Walk the returned dispatch table and invoke each provider-level
    //    entry point through it (so we exercise the function-pointer cast
    //    paths the same way OpenSSL does).
    OSSL_FUNC_provider_query_operation_fn   *qfn = NULL;
    OSSL_FUNC_provider_get_params_fn        *gpfn = NULL;
    OSSL_FUNC_provider_gettable_params_fn   *gtfn = NULL;
    OSSL_FUNC_provider_teardown_fn          *tdfn = NULL;
    for (const OSSL_DISPATCH *p = out_disp; p && p->function_id != 0; p++) {
        switch (p->function_id) {
        case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
            qfn = (OSSL_FUNC_provider_query_operation_fn *)p->function; break;
        case OSSL_FUNC_PROVIDER_GET_PARAMS:
            gpfn = (OSSL_FUNC_provider_get_params_fn *)p->function; break;
        case OSSL_FUNC_PROVIDER_GETTABLE_PARAMS:
            gtfn = (OSSL_FUNC_provider_gettable_params_fn *)p->function; break;
        case OSSL_FUNC_PROVIDER_TEARDOWN:
            tdfn = (OSSL_FUNC_provider_teardown_fn *)p->function; break;
        }
    }

    // 3. Query for OSSL_OP_RAND (expected) and a fuzzer-chosen op_id (mostly
    //    won't match anything, exercising the fall-through return NULL).
    if (qfn != NULL) {
        int no_cache = 0;
        (void)qfn(provctx, OSSL_OP_RAND, &no_cache);
        int unknown_op = (int)((flags & 0x7F) + 1000);  // outside known IDs
        (void)qfn(provctx, unknown_op, &no_cache);
    }

    // 4. Read provider params with a full set, plus a partial set chosen by
    //    the flag byte to vary which keys are present.
    if (gpfn != NULL && gtfn != NULL) {
        const OSSL_PARAM *gettable = gtfn(provctx);
        (void)gettable;

        const char *name_ptr = NULL, *ver_ptr = NULL, *build_ptr = NULL;
        int         status_v = 0;
        OSSL_PARAM full[] = {
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
        (void)gpfn(provctx, full);

        // Partial: include only one key, picked by the flag byte.
        int  pick      = flags & 0x03;
        const char *only_status = OSSL_PROV_PARAM_STATUS;
        const char *keys[4]     = { OSSL_PROV_PARAM_NAME,
                                    OSSL_PROV_PARAM_VERSION,
                                    OSSL_PROV_PARAM_BUILDINFO,
                                    only_status };
        OSSL_PARAM partial[2] = {
            { keys[pick], OSSL_PARAM_UTF8_PTR, &name_ptr,
              sizeof(name_ptr), 0 },
            OSSL_PARAM_END
        };
        if (pick == 3) {  // status is INTEGER, not UTF8_PTR
            partial[0].data_type = OSSL_PARAM_INTEGER;
            partial[0].data      = &status_v;
            partial[0].data_size = sizeof(status_v);
        }
        (void)gpfn(provctx, partial);

        // NULL params is documented as a no-op.
        (void)gpfn(provctx, NULL);
    }

    // 5. Type-mismatched params force OSSL_PARAM_set_* to fail cleanly,
    //    exercising the four "return 0" branches inside get_params that
    //    valid callers never reach.  set_utf8_ptr returns 0 when the
    //    declared type is not UTF8_PTR; set_int returns 0 when the type
    //    is not INTEGER.  We back the data with a real-sized buffer so
    //    the locate call returns this slot, but with the wrong type tag.
    if (gpfn != NULL) {
        int  buf_int  = 0;
        const char *buf_str = NULL;

        OSSL_PARAM bad_name[] = {
            { OSSL_PROV_PARAM_NAME,      OSSL_PARAM_INTEGER,  &buf_int,
              sizeof(buf_int), 0 },
            OSSL_PARAM_END
        };
        (void)gpfn(provctx, bad_name);

        OSSL_PARAM bad_version[] = {
            { OSSL_PROV_PARAM_VERSION,   OSSL_PARAM_INTEGER,  &buf_int,
              sizeof(buf_int), 0 },
            OSSL_PARAM_END
        };
        (void)gpfn(provctx, bad_version);

        OSSL_PARAM bad_buildinfo[] = {
            { OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_INTEGER,  &buf_int,
              sizeof(buf_int), 0 },
            OSSL_PARAM_END
        };
        (void)gpfn(provctx, bad_buildinfo);

        OSSL_PARAM bad_status[] = {
            { OSSL_PROV_PARAM_STATUS,    OSSL_PARAM_UTF8_PTR, &buf_str,
              sizeof(buf_str), 0 },
            OSSL_PARAM_END
        };
        (void)gpfn(provctx, bad_status);
    }

    // 6. Teardown.
    if (tdfn != NULL)
        tdfn(provctx);
    else
        OPENSSL_free(provctx);  // paranoia; teardown should be present

    return 0;
}
