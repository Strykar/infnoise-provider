// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// LibFuzzer harness: oracle-driven differential test of the three-phase
// generate algorithm.
//
// The fuzzer programs a hostile readData mock (via mock_set_chunk_script)
// with per-call return sizes that include short reads and explicit
// transients.  The harness then runs both the provider and an in-harness
// oracle - a faithful reimplementation of the spill-buffer contract -
// against the same script and entropy stream, and asserts byte-level
// agreement.
//
// What this catches that simple API-monkey harnesses cannot:
//   - Phase-3 short-read handling (returning success with an
//     uninitialised tail in the caller's buffer).
//   - Off-by-one in spill offset/length arithmetic across generate() calls.
//   - Wrong byte order on spill drain.
//   - Missing cleanse on the failure path.
//   - Out-of-bounds writes around outlen (caught by canary pages).
//
// Asserts (via __builtin_trap, which libFuzzer reports as a crash):
//   1. Canaries on either side of the output buffer remain intact.
//   2. Provider success/failure agrees with oracle success/failure.
//   3. On both-success: provider output equals oracle output, byte-for-byte.
//   4. On provider failure: output buffer is fully zeroed (cleanse-on-error).
//
// Input layout:
//   [u8]  num_gens     - (mod MAX_GENS) + 1, generate() calls per iteration
//   [u8]  num_chunks   - (mod MAX_CHUNKS) + 1, readData script length
//   [u16 LE] sizes[num_gens]  - per-generate outlen (mod MAX_OUTLEN)
//   [u8]  chunks[num_chunks]  - per-readData return size (mod BATCH_SIZE+1)
//   [...] entropy stream      - source bytes for readData

#include "../../src/infnoise_prov.c"
#include "mock_libinfnoise.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_GENS     8u
#define MAX_CHUNKS  32u
#define MAX_OUTLEN 1024u
#define CANARY     0xCDu
#define CANARY_PAD   64u

// ---------------------------------------------------------------------------
// Oracle: faithful reimplementation of the spill-buffer contract.
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t buf[BATCH_SIZE];
    size_t  off;
    size_t  len;
} OracleSpill;

// Mimics infnoise_read_device(): walks the chunk script, retrying on
// transients up to INFNOISE_MAX_ZERO_READS times, returning the bytes
// of one successful readData call (or 0 on hard failure).
static int32_t oracle_read(const uint8_t *chunks, size_t nc, size_t *ci,
                           const uint8_t *src,    size_t sn, size_t *si,
                           uint8_t       *out)
{
    int zeros = 0;
    while (zeros < INFNOISE_MAX_ZERO_READS) {
        if (*ci >= nc)
            return 0;
        uint32_t want = (uint32_t)chunks[(*ci)++] % (BATCH_SIZE + 1u);
        if (want == 0) { zeros++; continue; }
        if (*si + want > sn)
            want = (uint32_t)(sn - *si);
        if (want == 0)
            return 0;
        memcpy(out, src + *si, want);
        *si += want;
        return (int32_t)want;
    }
    return 0;
}

// Faithful reimplementation of infnoise_rand_generate's three-phase algorithm.
// Returns 0 on success, -1 on hard failure.
static int oracle_generate(OracleSpill *sp, uint8_t *out, size_t need,
                           const uint8_t *chunks, size_t nc, size_t *ci,
                           const uint8_t *src,    size_t sn, size_t *si)
{
    if (need == 0) return 0;
    size_t w = 0;

    // Phase 1: drain spill.
    size_t avail = sp->len - sp->off;
    size_t take  = avail < need ? avail : need;
    memcpy(out + w, sp->buf + sp->off, take);
    sp->off += take;
    w       += take;
    if (sp->off == sp->len) { sp->off = 0; sp->len = 0; }

    // Phase 2: full batches direct to caller.
    while (need - w >= BATCH_SIZE) {
        uint8_t tmp[BATCH_SIZE];
        int32_t got = oracle_read(chunks, nc, ci, src, sn, si, tmp);
        if (got <= 0) return -1;
        memcpy(out + w, tmp, (size_t)got);
        w += (size_t)got;
    }

    // Phase 3: tail.  Loop until satisfied; surplus on final read goes to spill.
    // (This mirrors the FIXED behaviour - see commit fixing phase-3 short reads.)
    while (w < need) {
        uint8_t tmp[BATCH_SIZE];
        int32_t got = oracle_read(chunks, nc, ci, src, sn, si, tmp);
        if (got <= 0) return -1;
        size_t give = (need - w) < (size_t)got ? (need - w) : (size_t)got;
        memcpy(out + w, tmp, give);
        w += give;
        if (give < (size_t)got) {
            memcpy(sp->buf, tmp + give, (size_t)got - give);
            sp->off = 0;
            sp->len = (size_t)got - give;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Deterministic assertion drives.
//
// These run once per LLVMFuzzerTestOneInput call after the oracle's
// byte-level invariants have been checked.  They cover provider surface
// the oracle alone cannot reach: get_ctx_params type-tag handling,
// get_seed entropy/length contract, strength-rejection at the boundary,
// and NULL-ctx handling on the lifecycle entry points.
//
// Inputs are fixed (independent of fuzzer bytes) so the corpus does not
// need to evolve to cover them - they execute on every iteration.
// ---------------------------------------------------------------------------

static const uint8_t kDriveEntropy[1024] = { 0 };

static void run_assertion_drives(void *ctx,
                                 const uint8_t *entropy,
                                 size_t entropy_n)
{
    // Reseed the mock so get_seed has entropy independent of what the
    // oracle just consumed.  Friendly mode (no chunk script) and a guaranteed-
    // sufficient buffer keep these drives deterministic.
    mock_set_chunk_script(NULL, 0);
    mock_set_init_failure(0);
    mock_set_fatal_after(0);
    if (entropy_n >= 256)
        mock_set_entropy(entropy, entropy_n);
    else
        mock_set_entropy(kDriveEntropy, sizeof(kDriveEntropy));

    // get_ctx_params: full set on the live ctx.
    int      state_v = -1;
    unsigned str_v   = 0;
    size_t   max_v   = 0;
    OSSL_PARAM cp_full[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE,          &state_v),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH,      &str_v),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &max_v),
        OSSL_PARAM_END
    };
    if (!infnoise_rand_get_ctx_params(ctx, cp_full)) __builtin_trap();
    if (str_v != INFNOISE_STRENGTH)                  __builtin_trap();
    if (max_v == 0)                                  __builtin_trap();
    if (state_v != EVP_RAND_STATE_READY
        && state_v != EVP_RAND_STATE_ERROR
        && state_v != EVP_RAND_STATE_UNINITIALISED)  __builtin_trap();

    // Type-mismatched STATE param must be rejected (declared int, asked for utf8).
    int        td = 0;
    OSSL_PARAM cp_bad_state[] = {
        { OSSL_RAND_PARAM_STATE, OSSL_PARAM_UTF8_PTR, &td, sizeof(td), 0 },
        OSSL_PARAM_END
    };
    if (infnoise_rand_get_ctx_params(ctx, cp_bad_state))    __builtin_trap();

    // Type-mismatched STRENGTH and MAX_REQUEST drive the other failure branches.
    OSSL_PARAM cp_bad_str[] = {
        { OSSL_RAND_PARAM_STRENGTH, OSSL_PARAM_UTF8_PTR, &td, sizeof(td), 0 },
        OSSL_PARAM_END
    };
    if (infnoise_rand_get_ctx_params(ctx, cp_bad_str))      __builtin_trap();

    OSSL_PARAM cp_bad_max[] = {
        { OSSL_RAND_PARAM_MAX_REQUEST, OSSL_PARAM_UTF8_PTR, &td, sizeof(td), 0 },
        OSSL_PARAM_END
    };
    if (infnoise_rand_get_ctx_params(ctx, cp_bad_max))      __builtin_trap();

    // NULL ctx must be rejected.
    if (infnoise_rand_get_ctx_params(NULL, cp_full))        __builtin_trap();

    // get_seed exercises only on a READY ctx; on ERROR or UNINIT the call
    // returns 0 by design, which would mask drive bugs.
    if (state_v != EVP_RAND_STATE_READY)
        return;

    // get_seed: NULL pout returns 0.
    if (infnoise_rand_get_seed(ctx, NULL, 0, 64, 64, 0, NULL, 0) != 0)
        __builtin_trap();

    // get_seed: zero-length returns 0.
    unsigned char *p = NULL;
    if (infnoise_rand_get_seed(ctx, &p, 0, 0, 0, 0, NULL, 0) != 0)
        __builtin_trap();

    // Reseed with a large buffer so the bigger seeds below have entropy.
    mock_set_entropy(kDriveEntropy, sizeof(kDriveEntropy));

    // get_seed credits min-entropy, not raw byte count: it returns
    // ceil(entropy / INFNOISE_MINENT_PER_OUTBYTE) rounded UP to a whole
    // BATCH_SIZE device block, so the seed is whole Keccak squeezes that carry
    // the entropy the DRBG credits it.  256 bits -> ceil(256/3)=86 -> 128
    // bytes (2 blocks).
    p = NULL;
    size_t got = infnoise_rand_get_seed(ctx, &p, 256, 32, 256, 0, NULL, 0);
    if (got != 128)                                         __builtin_trap();
    OPENSSL_secure_clear_free(p, got);

    // Block-rounding boundary: 192 bits -> ceil(192/3)=64 = exactly 1 block;
    // 193 bits -> ceil(193/3)=65 -> rounds up to 2 blocks (128).  min_len=1 so
    // the entropy term drives; kills off-by-one in the ceil and the rounding.
    p = NULL; got = infnoise_rand_get_seed(ctx, &p, 192, 1, 256, 0, NULL, 0);
    if (got != 64)  __builtin_trap();  OPENSSL_secure_clear_free(p, got);
    p = NULL; got = infnoise_rand_get_seed(ctx, &p, 193, 1, 256, 0, NULL, 0);
    if (got != 128) __builtin_trap();  OPENSSL_secure_clear_free(p, got);

    // Entropy whose whole-block size exceeds max_len must reject without
    // touching *pout (the seed would be over-credited otherwise).
    p = (unsigned char *)(uintptr_t)0xDEADBEEFUL;
    got = infnoise_rand_get_seed(ctx, &p, 256, 32, 64, 0, NULL, 0);
    if (got != 0)                                           __builtin_trap();
    if (p != (unsigned char *)(uintptr_t)0xDEADBEEFUL)      __builtin_trap();

    // Boundary: when the whole-block size equals max_len exactly, the seed
    // fits and must be returned -- the compare is strict '>' (reject only when
    // it exceeds), not '>='.  256 bits rounds to 128, so with max_len == 128
    // the seed is accepted.  Pins the strict bound against an off-by-one.
    p = NULL; got = infnoise_rand_get_seed(ctx, &p, 256, 32, 128, 0, NULL, 0);
    if (got != 128) __builtin_trap();  OPENSSL_secure_clear_free(p, got);

    // Small positive entropy still gets a whole block (64), and min_len=32
    // does not undercut it.
    p = NULL; got = infnoise_rand_get_seed(ctx, &p, 8, 32, 256, 0, NULL, 0);
    if (got != 64) __builtin_trap();  OPENSSL_secure_clear_free(p, got);

    // entropy <= 0: no entropy requirement, return the min_len floor unrounded.
    p = NULL; got = infnoise_rand_get_seed(ctx, &p, 0, 32, 256, 0, NULL, 0);
    if (got != 32) __builtin_trap();  OPENSSL_secure_clear_free(p, got);

    // Spill alignment (regression for the cross-call straddle Codex found on
    // PR #21).  A non-block-aligned generate() leaves a partial block in the
    // spill; get_seed() must flush it so the seed is whole aligned blocks, not
    // a slice of an old block + a whole block + a slice of a new one (which is
    // only one complete block, below the credited entropy in the worst case).
    SpillBufferInit(&((PROV_INFNOISE *)ctx)->spill);
    mock_set_entropy(kDriveEntropy, sizeof(kDriveEntropy));
    {
        uint8_t one[1];
        if (!infnoise_rand_generate(ctx, one, 1, INFNOISE_STRENGTH, 0, NULL, 0))
            __builtin_trap();
        // generate(1) read a 64-byte block and stored the 63-byte remainder.
        if (((PROV_INFNOISE *)ctx)->spill.length != 63)        __builtin_trap();
        p = NULL;
        got = infnoise_rand_get_seed(ctx, &p, 256, 32, 256, 0, NULL, 0);
        if (got != 128)                                        __builtin_trap();
        // get_seed flushed the spill and read whole aligned blocks, so the
        // spill is empty.  Without the flush it would hold 63 bytes here.
        if (((PROV_INFNOISE *)ctx)->spill.length != 0)         __builtin_trap();
        OPENSSL_secure_clear_free(p, got);
    }
}

static void run_strength_boundary_drive(void)
{
    // A fresh ctx so we don't disturb the main test's ctx state.
    void *c2 = infnoise_rand_newctx(NULL, NULL, NULL);
    if (c2 == NULL) return;

    // strength > INFNOISE_STRENGTH must reject (line 220 mutants).
    if (infnoise_rand_instantiate(c2, INFNOISE_STRENGTH + 1u,
                                  0, NULL, 0, NULL))
        __builtin_trap();

    // strength == INFNOISE_STRENGTH must accept on the same ctx.
    if (!infnoise_rand_instantiate(c2, INFNOISE_STRENGTH,
                                   0, NULL, 0, NULL))
        __builtin_trap();

    infnoise_rand_uninstantiate(c2);
    infnoise_rand_freectx(c2);
}

// ---------------------------------------------------------------------------
// Fuzz entry point.
// ---------------------------------------------------------------------------

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return -1;

    // Header byte 0 carries injection flags, read once up front.
    uint8_t inj         = data[0];
    int     fail_init   = (inj & 0x01) != 0;
    int     fatal_read  = (inj & 0x02) != 0;     // mock returns negative
    int     do_locking  = (inj & 0x04) != 0;     // exercise lock/unlock pair
    int     bad_parent  = (inj & 0x08) != 0;     // pass non-NULL parent

    uint8_t num_gens   = (uint8_t)((data[1] % MAX_GENS  ) + 1u);
    uint8_t num_chunks = (uint8_t)((data[2] % MAX_CHUNKS) + 1u);

    size_t pos = 3;
    if (size < pos + 2u * num_gens + num_chunks) return -1;

    uint16_t sizes[MAX_GENS];
    size_t total = 0;
    for (uint8_t i = 0; i < num_gens; i++) {
        sizes[i] = (uint16_t)(((uint16_t)data[pos]
                              | ((uint16_t)data[pos + 1] << 8))
                              % MAX_OUTLEN);
        total += sizes[i];
        pos   += 2;
    }
    if (total == 0) return -1;

    const uint8_t *chunks    = data + pos; pos += num_chunks;
    const uint8_t *entropy   = data + pos;
    size_t         entropy_n = size - pos;

    // --- Compute oracle's expected output ---
    uint8_t *expected = malloc(total);
    if (!expected) return 0;

    OracleSpill osp = {{0}, 0, 0};
    size_t ci_o = 0, si_o = 0, w_o = 0;
    int oracle_ok = 1;
    for (uint8_t i = 0; i < num_gens; i++) {
        if (oracle_generate(&osp, expected + w_o, sizes[i],
                            chunks, num_chunks, &ci_o,
                            entropy, entropy_n, &si_o) != 0) {
            oracle_ok = 0;
            break;
        }
        w_o += sizes[i];
    }

    // --- Run the provider against the same script ---
    mock_set_chunk_script(chunks, num_chunks);
    mock_set_entropy(entropy, entropy_n);
    mock_set_init_failure(fail_init);
    mock_set_fatal_after(fatal_read ? 1u : 0u);

    // newctx must reject a non-NULL parent (seed sources must not chain).
    void *fake_parent = bad_parent ? (void *)(uintptr_t)0xDEAD : NULL;
    void *ctx = infnoise_rand_newctx(NULL, fake_parent, NULL);
    if (bad_parent) {
        if (ctx != NULL) __builtin_trap();
        free(expected);
        goto done;
    }
    // OPENSSL_zalloc has no reason to fail under the mock; treat NULL as a bug.
    if (!ctx) __builtin_trap();

    if (do_locking)
        infnoise_rand_enable_locking(ctx);

    if (!infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH, 0, NULL, 0, NULL)) {
        // Failure is only expected when the mock was told to inject one.
        // Anything else is a bug (e.g., a strength-check mutation).
        if (!fail_init) __builtin_trap();
        free(expected);
        infnoise_rand_freectx(ctx);
        goto done;
    }

    // Single safe lock/unlock pair around the generate sequence.  We never
    // re-lock without unlock, so no deadlock is possible.
    if (do_locking)
        infnoise_rand_lock(ctx);

    // Sandwich the output in canary pads to catch out-of-bounds writes.
    uint8_t *block = malloc(CANARY_PAD + total + CANARY_PAD);
    if (!block) {
        free(expected);
        infnoise_rand_freectx(ctx);
        goto done;
    }
    memset(block, CANARY, CANARY_PAD + total + CANARY_PAD);
    uint8_t *actual = block + CANARY_PAD;

    int    provider_ok  = 1;
    int    failed_at    = -1;     // index of the call that failed, or -1
    size_t fail_offset  = 0;      // offset of failed call's output in actual[]
    size_t w_p          = 0;
    for (uint8_t i = 0; i < num_gens; i++) {
        if (!infnoise_rand_generate(ctx, actual + w_p, sizes[i],
                                    INFNOISE_STRENGTH, 0, NULL, 0)) {
            failed_at   = (int)i;
            fail_offset = w_p;
            provider_ok = 0;
            break;
        }
        w_p += sizes[i];
    }

    // --- Invariants ---

    // 1. Canaries intact.
    for (size_t i = 0; i < CANARY_PAD; i++) {
        if (block[i] != CANARY) __builtin_trap();
        if (block[CANARY_PAD + total + i] != CANARY) __builtin_trap();
    }

    // 2. Success/failure must agree between oracle and provider.
    //    Skip when fatal_read is set: the mock injects an error the oracle
    //    doesn't model, so divergence is expected.
    if (!fatal_read && oracle_ok != provider_ok) __builtin_trap();

    // 3. On both-success: outputs match.
    if (!fatal_read && oracle_ok && provider_ok) {
        if (memcmp(actual, expected, total) != 0) __builtin_trap();
    }

    // 4. On provider failure (after read attempts): the failed call's output
    //    range must be fully cleansed.  Don't inspect un-attempted calls;
    //    their output region is whatever the caller-supplied buffer held.
    //    This invariant holds regardless of whether failure was natural or
    //    injected — provider must always cleanse on failure.
    if (failed_at >= 0) {
        for (size_t j = fail_offset; j < fail_offset + sizes[failed_at]; j++)
            if (actual[j] != 0) __builtin_trap();
    }

    // Drive surfaces the oracle does not exercise: params, get_seed, and
    // the strength boundary on a sibling ctx.  Done while the lock is still
    // held - none of these acquire the lock internally.
    run_assertion_drives(ctx, entropy, entropy_n);
    run_strength_boundary_drive();

    if (do_locking)
        infnoise_rand_unlock(ctx);

    // Uninstantiate -> verify cycle: clean ctx returns 1, dirty returns 0.
    if (!infnoise_rand_uninstantiate(ctx))             __builtin_trap();
    if (!infnoise_rand_verify_zeroization(ctx))        __builtin_trap();
    ((PROV_INFNOISE *)ctx)->spill.data[0] = 0xFF;
    if (infnoise_rand_verify_zeroization(ctx))         __builtin_trap();
    ((PROV_INFNOISE *)ctx)->spill.data[0] = 0x00;

    // NULL ctx must be safe on every lifecycle entry point.
    if (infnoise_rand_uninstantiate(NULL))             __builtin_trap();
    if (infnoise_rand_verify_zeroization(NULL))        __builtin_trap();
    infnoise_rand_freectx(NULL);

    free(block);
    free(expected);
    infnoise_rand_freectx(ctx);

done:
    // Reset all mock state so injection flags don't leak across inputs.
    mock_set_chunk_script(NULL, 0);
    mock_set_entropy(NULL, 0);
    mock_set_init_failure(0);
    mock_set_fatal_after(0);
    return 0;
}
