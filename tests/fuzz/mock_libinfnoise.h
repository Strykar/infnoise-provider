// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
#pragma once
#include <stddef.h>
#include <stdint.h>

// Seed the mock's entropy buffer before calling the provider.
// readData() draws from this buffer; returns 0 (transient) when exhausted.
void mock_set_entropy(const uint8_t *data, size_t len);

// Optional: program a hostile chunk-size script.  When set, each readData()
// call consumes one script byte and returns (byte % (BATCH_SIZE+1)) bytes,
// so the fuzzer can exercise short reads and explicit transients.  Pass
// NULL to restore the default friendly mode (return as much as possible).
void mock_set_chunk_script(const uint8_t *data, size_t len);

// Optional: failure-injection knobs.  Default to "off" (mock behaves
// successfully).  Reset to off by passing 0.
//   fail_init:     non-zero → initInfnoise() returns false (sets a fake
//                  error message into ctx->message before returning).
//   fatal_after_n: non-zero → the n-th readData() call (1-based) returns
//                  INFNOISE_ERR_USB_READ instead of bytes; subsequent
//                  calls return 0 (transient).  Tests provider's fatal-
//                  error transition.
void mock_set_init_failure(int fail_init);
void mock_set_fatal_after(uint32_t n);
