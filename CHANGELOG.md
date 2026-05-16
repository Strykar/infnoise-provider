# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Pre-1.0 versions remain incompatible-by-default; see the alpha-status note in
[README.md](README.md). The first signed release is gated on the external
cryptographic review described in [docs/Security_Review.txt](docs/Security_Review.txt).

## [Unreleased]

### Security

- Fix phase-3 short-read memory disclosure in `infnoise_rand_generate`. When
  `infnoise_read_device` returned `n < remaining` in the tail phase, the
  function copied only `n` bytes and returned success, leaving the rest of
  the caller's output buffer as uninitialised heap. Today's libinfnoise
  always returns `BATCH_SIZE`, so the defect was latent; a different output
  multiplier or libinfnoise variant could trigger memory disclosure into
  cryptographic output buffers. Found by the new differential oracle
  fuzz harness. Regression input under `fuzz/regressions/phase3_short_read.bin`.
  ([#9](https://github.com/Strykar/infnoise-provider/pull/9))
- Fix zero-outlen NULL pointer-arithmetic UB. `infnoise_rand_generate(out=NULL,
  outlen=0)` walked past the early validation checks and computed
  `unsigned char *w_ptr = NULL; w_ptr += 0;`, which is undefined behaviour
  per ISO C. Caught by UBSan in the CIFuzz workflow's first-PR run.
  Regression input under `fuzz/regressions/zero_outlen_null_ptr.bin`.
  ([#9](https://github.com/Strykar/infnoise-provider/pull/9))
- Fix FTDI handle leak when `infnoise_rand_uninstantiate` is called on an
  ERROR-state context. The previous condition only deinit'd on READY, then
  cleansed `trng_context`, dropping the libftdi pointer on the floor.
  Recovery patterns of (instantiate, fail, uninstantiate, instantiate)
  would race the second instantiate against a still-open libftdi context.
  Same fix applied to `infnoise_rand_instantiate` for the
  re-instantiate-after-error path. ([#10](https://github.com/Strykar/infnoise-provider/pull/10))
- `infnoise_rand_get_seed` now honours the `entropy` parameter. The TRNG
  delivers full entropy (8 bits per byte after Keccak whitening), so a
  buffer of `len` bytes can carry at most `8 * len` bits; requests
  exceeding this now reject rather than silently undershoot.
  ([#10](https://github.com/Strykar/infnoise-provider/pull/10))
- `infnoise_rand_verify_zeroization` now checks both the spill buffer and
  `trng_context` are cleansed, not just the spill. The function's
  documented contract called for both; only the former was verified.
  ([#10](https://github.com/Strykar/infnoise-provider/pull/10))

### Added

- Four-target libFuzzer harness suite under `fuzz/`: `fuzz_dispatch` (state
  machine), `fuzz_ossl_params` (OSSL_PARAM surface), `fuzz_spill_oracle`
  (differential test against an in-harness reference; this is what found
  the phase-3 bug), `fuzz_provider_init` (`OSSL_provider_init` / query /
  get_params / teardown). Mock libinfnoise stub so no USB device is
  needed. See [docs/Fuzz_Coverage.txt](docs/Fuzz_Coverage.txt).
  ([#9](https://github.com/Strykar/infnoise-provider/pull/9))
- Persistent fuzz corpus committed under `fuzz/corpus/<harness>/` (~505
  inputs, ~2 MiB) so each CI / local fuzz run starts from accumulated
  coverage rather than empty. Regression-input directory under
  `fuzz/regressions/` with the two inputs that triggered fixed bugs;
  cifuzz replays both before the timed runs.
- ThreadSanitizer concurrency stress test (`make test-tsan`,
  [tests/test_infnoise_tsan.c](tests/test_infnoise_tsan.c)). Two scenarios,
  4 threads × 20,000 iterations: shared context with provider locking,
  and per-thread contexts. Mock libinfnoise pthread-mutex-protected so
  the per-thread-context scenario is race-free at the harness layer.
- Allocator-failure injection test (`make test-alloc`,
  [tests/test_infnoise_alloc.c](tests/test_infnoise_alloc.c)). Installs
  `CRYPTO_set_mem_functions` hooks that fail on demand and drives four
  alloc sites: `newctx` zalloc, `OSSL_provider_init` zalloc,
  `enable_locking` lock_new, `get_seed` secure_malloc.
- `evp_rand_error_codes` test in the integration harness asserts the
  right `PROV_R_*` reason codes on documented failure paths
  (`PROV_R_INSUFFICIENT_DRBG_STRENGTH`, `PROV_R_NOT_INSTANTIATED`).
  Test count 27 → 28.
- `make sbom` target produces an SPDX-2.3 software bill of materials
  at `sbom.spdx.txt` (provider + libcrypto + libftdi1 + libusb-1.0 +
  libinfnoise). No external SBOM tooling required.
- `make test-soak` now captures raw TRNG output and renders pair-wise
  scatter and byte-value heatmap comparisons of raw vs Keccak-whitened
  output (visible under `docs/endurance-24h-*.png`).
- CIFuzz workflow runs all five fuzz harnesses on every PR (60 s/target)
  and push (120 s/target), replays the regression inputs first.
- New documentation: `docs/Fuzz_Coverage.txt` (per-function coverage
  report), `docs/Security_Review.txt` (brief for an external
  cryptographic reviewer), `docs/Governance.txt` (single-maintainer
  model, signing-key plan, account-compromise procedure).
- Compatibility shim for `OSSL_DISPATCH_END` so the provider builds
  against OpenSSL 3.0–3.2 (Ubuntu 22.04, Debian bookworm) where the
  macro doesn't exist.
- Inline `// SECURITY: reviewed YYYY-MM-DD` markers at the six
  alloc-failure paths after manual audit.
- Defense-in-depth NULL checks on `instantiate`, `uninstantiate`, and
  `get_seed` dispatch entries (matches the existing pattern in
  `freectx` and the locking entries; diverges from upstream OpenSSL's
  RAND providers, which omit the checks throughout).
  ([#11](https://github.com/Strykar/infnoise-provider/pull/11))
- `OSSL_provider_init` zeros `*provctx` and `*out` at function entry so
  a misbehaving loader that ignores the return value can't deref garbage.
- `make mutation` target for release-prep mutation testing using
  [Mull](https://github.com/mull-project/mull). The pool is scoped to
  `src/infnoise_prov.c` via `mull.yml` so the score reflects provider
  assertions, not harness self-tests. Toolchain pins to `mull-bin` and
  `clang20` on Arch (Mull's plugin loads only into the LLVM major it
  was built against). Run before tagging a signed release;
  score-before vs score-after on the touched files is the audit
  signal. Documented in [docs/CONTRIBUTING.txt](docs/CONTRIBUTING.txt) §4
  under "Optional, release-prep only".
- `examples/python_demo.py` — Python keygen via the `cryptography`
  package, demonstrating that any libcrypto-backed Python operation
  picks up the provider when `OPENSSL_CONF` points at the bundled
  config. Validated in a containerised build with USB device
  passthrough.
- `examples/systemd-drop-in.conf` — systemd drop-in that scopes
  `OPENSSL_CONF` to a single service (nginx, sshd, postfix, etc.),
  leaving the rest of the host on its default RNG. Validated by
  installing under `/etc/systemd/system/<unit>.service.d/`,
  `systemd-analyze verify` passes, the service runs `openssl rand`
  through the dropped-in config.
- [docs/FAQ.txt](docs/FAQ.txt) — six questions covering provider vs.
  ENGINE, provider vs. `/dev/hwrng` + rngd, TLS speed, daemon
  coexistence, runtime device-unplug recovery, and when the kernel
  CSPRNG is the right choice instead of this provider.

### Changed

- libinfnoise patches merged into upstream `waywardgeek/infnoise`
  master on 2026-05-15
  ([#121](https://github.com/waywardgeek/infnoise/pull/121) moved
  Keccak / health state into the per-device context;
  [#122](https://github.com/waywardgeek/infnoise/pull/122) added the
  `infnoise_error_t` enum and switched `readData()` to signed
  `int32_t`). The provider's `#ifndef INFNOISE_KECCAK_STATE_SIZE /
  #error` guard is unchanged; the Strykar/infnoise fork is no longer
  required, and the five CI workflows
  (`build` / `cifuzz` / `codeql` / `coverity` / `sanitizers`) clone
  `waywardgeek/infnoise` master directly. Docs swept:
  [README.md](README.md) §Requirements + install snippets,
  [docs/ARCHITECTURE.txt](docs/ARCHITECTURE.txt) §4 + §6,
  [docs/CONTRIBUTING.txt](docs/CONTRIBUTING.txt) §6 + §7,
  [docs/Governance.txt](docs/Governance.txt) §3 + §5,
  [docs/TODO.txt](docs/TODO.txt) release gate.
- Hard-require libinfnoise with per-context Keccak/health state and
  signed-`int32_t` `readData()` via `#ifndef
  INFNOISE_KECCAK_STATE_SIZE / #error`. Both properties are upstream
  in `waywardgeek/infnoise` master (see entry above); older
  libinfnoise builds fail with a clear `#error`.
- Phase 3 of `infnoise_rand_generate` now loops on short reads from
  `infnoise_read_device`, mirroring phase 2. Previously it took only
  one read and returned (the source of the disclosure bug above).
- `infnoise_rand_get_seed`'s `entropy` parameter is now honoured (was
  marked `UNUSED`).
- `OSSL_provider_init` defensively zeros out parameters at function
  entry.
- Replaced the local `UNUSED` macro with `ossl_unused` from
  `<openssl/e_os2.h>` to match upstream OpenSSL convention.
  ([#12](https://github.com/Strykar/infnoise-provider/pull/12))
- Replaced `{ 0, NULL }` dispatch-table sentinels with
  `OSSL_DISPATCH_END` (with the OpenSSL 3.0–3.2 compat shim above).
  ([#12](https://github.com/Strykar/infnoise-provider/pull/12))
- Switched the oversized-request error in `generate` from
  `ERR_R_PASSED_INVALID_ARGUMENT` to `PROV_R_REQUEST_TOO_LARGE_FOR_DRBG`
  to match upstream DRBG providers.
  ([#12](https://github.com/Strykar/infnoise-provider/pull/12))
- Renamed `doc/` to `docs/` (the GitHub-Pages-conventional plural form).
  All cross-references swept; rename history preserved via `git mv`.
- Renamed `test/` to `tests/` (same convention reasoning); `fuzz/`
  stays at the repository root because libFuzzer documentation and
  OSS-Fuzz onboarding scripts default to that location.
- README test arsenal section expanded from a single sentence to a
  per-target inventory; added the OSTIF-required reproducibility,
  SBOM, and secure-heap caveats to relevant docs; updated the alpha
  callout from "passes its own test harness and sanitizer runs" to a
  concrete claim.
- `docs/CONTRIBUTING.txt` updated with the new test gates
  (`test-tsan`, `test-alloc`, `make fuzz`) and a security-feeds
  subscription policy.
- `fuzz_spill_oracle.c` extended with deterministic assertion drives
  for the OSSL_PARAM surface (full set, type-mismatched data tags,
  NULL ctx), the `get_seed` contract (NULL `pout`, `len=0`,
  `max_len < min_len`, `entropy > 8*len` rejection), strength
  rejection at `INFNOISE_STRENGTH+1` on a sibling ctx, and
  NULL-ctx safety on `uninstantiate` / `freectx` /
  `verify_zeroization`. Three previously-silent skip-paths now trap:
  `bad_parent` must be rejected, `instantiate` must succeed when
  `fail_init=0`, and `verify_zeroization` returns are asserted (was
  `(void)`). Existing 196-input corpus replays cleanly under
  libFuzzer.

### Removed

- `INFNOISE_PATCHED` compile-time bridge and the entire unpatched
  libinfnoise fallback code path (~30 lines from
  `infnoise_read_device`). The provider no longer supports unpatched
  upstream `waywardgeek/infnoise`. ([#9](https://github.com/Strykar/infnoise-provider/pull/9))
- Two unpatched-related entries from the README "Known limitations"
  section.
- The old `(char *)(uintptr_t)kInfnoiseSerial` round-trip cast (the
  `(uintptr_t)` part was a no-op for the current `NULL` value).
  ([#11](https://github.com/Strykar/infnoise-provider/pull/11))
- `fuzz_params.c` harness and its 80-input corpus. The boundary-fuzzing
  surface (32-bit `outlen` and `strength`, addin pass-through, linear
  newctx → instantiate → generate → teardown flow) was already covered
  by `fuzz_dispatch`'s state-machine fuzzer with 32-bit op parameters.
  No regression input pointed to `fuzz_params`. CIFuzz now runs four
  targets per push instead of five.

### Fixed

- `fuzz_dispatch` harness deadlocked when the fuzzer drove two
  consecutive `lock` operations against an `enable_locking`-prepared
  context. POSIX rwlocks are non-recursive; the harness's
  state-machine ops have been narrowed from 12 to 9, dropping
  `enable_locking`/`lock`/`unlock` (the lock primitives are pure
  delegation to OpenSSL and are exercised by the sanitiser test
  suite, not the fuzzer). ([#9](https://github.com/Strykar/infnoise-provider/pull/9))

## [0.0.1-alpha] - 2026-04-12

Initial alpha release. The provider implements `OSSL_OP_RAND` for
OpenSSL 3.x backed by the Infinite Noise TRNG. See README for the
detailed feature inventory at this snapshot.

[Unreleased]: https://github.com/Strykar/infnoise-provider/compare/v0.0.1-alpha...HEAD
[0.0.1-alpha]: https://github.com/Strykar/infnoise-provider/releases/tag/v0.0.1-alpha
