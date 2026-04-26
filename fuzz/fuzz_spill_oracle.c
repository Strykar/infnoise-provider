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

#include "../src/infnoise_prov.c"
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

    // Exercise the parent-check error path occasionally.
    void *fake_parent = bad_parent ? (void *)(uintptr_t)0xDEAD : NULL;
    void *ctx = infnoise_rand_newctx(NULL, fake_parent, NULL);
    if (!ctx) { free(expected); goto done; }

    if (do_locking)
        infnoise_rand_enable_locking(ctx);

    if (!infnoise_rand_instantiate(ctx, INFNOISE_STRENGTH, 0, NULL, 0, NULL)) {
        // Instantiate-failure path is intentional when fail_init is set;
        // the harness oracle would also fail here.  Skip generate.
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

    if (do_locking)
        infnoise_rand_unlock(ctx);

    // Cycle through uninstantiate -> verify_zeroization.  After uninstantiate
    // the spill buffer is cleansed and verify returns 1 (success branch).
    // To also cover the "non-zero spill" failure branch, poke a byte into
    // the spill, then call verify a second time; the harness must know the
    // PROV_INFNOISE layout, which it does (via the #include).
    infnoise_rand_uninstantiate(ctx);
    (void)infnoise_rand_verify_zeroization(ctx);  // success branch
    ((PROV_INFNOISE *)ctx)->spill.data[0] = 0xFF;
    (void)infnoise_rand_verify_zeroization(ctx);  // failure branch
    ((PROV_INFNOISE *)ctx)->spill.data[0] = 0x00;

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
