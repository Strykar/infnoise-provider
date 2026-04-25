// LibFuzzer harness: dispatch-table state machine coverage.
//
// The fuzzer controls both the sequence of operations and their parameters,
// letting it discover invalid state transitions the provider must survive:
// double-instantiate, generate before instantiate, generate after error,
// freectx while instantiated, etc.
//
// Input encoding — greedy loop until bytes exhausted:
//   [u8] opcode  (mod NUM_OPS selects operation)
//   [u8] ctx_idx (mod MAX_CTX selects context slot)
//   [op-specific bytes] see switch below
//
// Up to MAX_CTX contexts are maintained in a pool; NULL slots are skipped
// for operations that would dereference the pointer (instantiate, generate,
// uninstantiate, reseed, get_seed).  freectx() handles NULL gracefully and
// is always called at the end for cleanup.
//
// enable_locking / lock / unlock are intentionally absent: CRYPTO_RWLOCK is
// non-recursive, so any fuzzer-driven sequence with two consecutive locks
// trivially deadlocks.  Lock primitives are pure delegation to OpenSSL and
// are exercised by the sanitizer test suite, not here.

#include "../src/infnoise_prov.c"
#include "mock_libinfnoise.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CTX 4
#define NUM_OPS 9

// Consume bytes from the fuzz stream.
static uint8_t  take_u8 (const uint8_t **p, size_t *r) { if (!*r) return 0; uint8_t v = **p; (*p)++; (*r)--; return v; }
static uint32_t take_u32(const uint8_t **p, size_t *r)
{
    uint32_t v = 0;
    for (int i = 0; i < 4 && *r; i++) { v |= (uint32_t)(**p) << (i*8); (*p)++; (*r)--; }
    return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    void *ctxs[MAX_CTX] = {NULL};

    const uint8_t *p   = data;
    size_t         rem = size;

    while (rem > 0) {
        uint8_t op = take_u8(&p, &rem) % NUM_OPS;
        uint8_t ci = take_u8(&p, &rem) % MAX_CTX;

        switch (op) {
        case 0: // newctx — allocate into slot if empty
            if (!ctxs[ci])
                ctxs[ci] = infnoise_rand_newctx(NULL, NULL, NULL);
            break;

        case 1: // freectx — freectx(NULL) is a defined no-op
            infnoise_rand_freectx(ctxs[ci]);
            ctxs[ci] = NULL;
            break;

        case 2: { // instantiate — strength byte * 2 gives 0..510 range
            if (!ctxs[ci]) break;
            uint8_t s = take_u8(&p, &rem);
            // Seed with remaining bytes so generate can be reached
            mock_set_entropy(p, rem);
            infnoise_rand_instantiate(ctxs[ci], (unsigned)s * 2,
                                       0, NULL, 0, NULL);
            break;
        }

        case 3: // uninstantiate
            if (!ctxs[ci]) break;
            infnoise_rand_uninstantiate(ctxs[ci]);
            break;

        case 4: { // generate
            if (!ctxs[ci]) break;
            uint32_t olen = take_u32(&p, &rem);
            uint8_t  s    = take_u8(&p, &rem);
            size_t   safe = (olen <= INFNOISE_MAX_REQUEST) ? olen : 0;
            uint8_t *out  = safe > 0 ? malloc(safe) : NULL;
            if (safe == 0 || out) {
                mock_set_entropy(p, rem);
                infnoise_rand_generate(ctxs[ci], out, olen,
                                       (unsigned)s * 2, 0, NULL, 0);
            }
            free(out);
            break;
        }

        case 5: // reseed (no-op in this provider, but exercises ctx deref)
            if (!ctxs[ci]) break;
            infnoise_rand_reseed(ctxs[ci], 0, NULL, 0, NULL, 0);
            break;

        case 6: { // get_ctx_params
            int      state_v = 0;
            unsigned str_v   = 0;
            size_t   max_v   = 0;
            OSSL_PARAM params[] = {
                OSSL_PARAM_int(OSSL_RAND_PARAM_STATE,          &state_v),
                OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH,      &str_v),
                OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_v),
                OSSL_PARAM_END
            };
            infnoise_rand_get_ctx_params(ctxs[ci], params);
            break;
        }

        case 7: // verify_zeroization
            infnoise_rand_verify_zeroization(ctxs[ci]);
            break;

        case 8: { // get_seed
            if (!ctxs[ci]) break;
            uint8_t min_b = take_u8(&p, &rem);
            uint8_t max_b = take_u8(&p, &rem);
            // Don't pre-clamp: let the fuzzer drive both max < min (which
            // hits the "max_len < len" clamp inside get_seed) and max >= min.
            size_t  min_l = min_b;
            size_t  max_l = max_b;
            unsigned char *sout = NULL;
            mock_set_entropy(p, rem);
            size_t got = infnoise_rand_get_seed(ctxs[ci], &sout, 256,
                                                min_l, max_l, 0, NULL, 0);
            if (sout)
                infnoise_rand_clear_seed(ctxs[ci], sout, got);
            break;
        }
        }
    }

    // Clean up: freectx(NULL) is safe, instantiated contexts are deinited.
    for (int i = 0; i < MAX_CTX; i++)
        infnoise_rand_freectx(ctxs[i]);

    return 0;
}
