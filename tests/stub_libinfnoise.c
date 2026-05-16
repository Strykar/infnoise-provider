// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// CI-only libinfnoise drop-in.  Provides initInfnoise / deinitInfnoise /
// readData by drawing from /dev/urandom so the example-driving CI
// workflow can exercise the provider on a GitHub runner where no
// Infnoise hardware is plugged in.
//
// Build:
//   make tests/libinfnoise.so          # produces a CI stub libinfnoise.so
//
// Install (CI only):
//   sudo install -m 755 tests/libinfnoise.so /usr/lib/libinfnoise.so
//
// Not for production use.  The /dev/urandom output is the kernel
// CSPRNG, not the Infnoise device; the stub exists only to give the
// provider's link/runtime path something to bind to in test
// environments without hardware.

#include <libinfnoise.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

#define STUB_BATCH 64u

static int g_fd = -1;

bool initInfnoise(struct infnoise_context *ctx, char *serial,
                  bool keccak, bool debug)
{
    (void)serial; (void)keccak; (void)debug;
    g_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (g_fd < 0) {
        ctx->message = "stub: cannot open /dev/urandom";
        return false;
    }
    ctx->message = NULL;
    return true;
}

void deinitInfnoise(struct infnoise_context *ctx)
{
    (void)ctx;
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

int32_t readData(struct infnoise_context *ctx, uint8_t *result,
                 bool raw, uint32_t outputMultiplier)
{
    (void)raw; (void)outputMultiplier;
    if (g_fd < 0) {
        ctx->message = "stub: initInfnoise was not called";
        return INFNOISE_ERR_USB_READ;
    }
    ssize_t n = read(g_fd, result, STUB_BATCH);
    if (n < 0) {
        ctx->message = "stub: /dev/urandom read failed";
        return INFNOISE_ERR_USB_READ;
    }
    return (int32_t)n;
}
