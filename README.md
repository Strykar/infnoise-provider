# infnoise-provider

[![build](https://github.com/Strykar/infnoise-provider/actions/workflows/build.yml/badge.svg)](https://github.com/Strykar/infnoise-provider/actions/workflows/build.yml)
[![sanitizers](https://github.com/Strykar/infnoise-provider/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/Strykar/infnoise-provider/actions/workflows/sanitizers.yml)
[![CodeQL](https://github.com/Strykar/infnoise-provider/actions/workflows/codeql.yml/badge.svg)](https://github.com/Strykar/infnoise-provider/actions/workflows/codeql.yml)
[![cppcheck](https://github.com/Strykar/infnoise-provider/actions/workflows/cppcheck.yml/badge.svg)](https://github.com/Strykar/infnoise-provider/actions/workflows/cppcheck.yml)
[![Coverity Scan](https://scan.coverity.com/projects/Strykar-infnoise-provider/badge.svg)](https://scan.coverity.com/projects/Strykar-infnoise-provider)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12494/badge)](https://www.bestpractices.dev/projects/12494)
[![Language: C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

OpenSSL 3.x [provider](https://docs.openssl.org/3.4/man7/provider) for the [Infinite Noise TRNG](https://github.com/waywardgeek/infnoise) hardware random number generator.

This provider registers an `OSSL_OP_RAND` seed source backed by the Infinite Noise TRNG, a USB true random number generator based on modular entropy multiplication.  When configured as the DRBG seed source, all OpenSSL cryptographic operations (key generation, signatures, TLS handshakes) are seeded with hardware entropy.

Written from scratch for the OpenSSL 3.x Provider API.  A legacy `ENGINE` implementation by Tim Skipper exists at [tinskip/infnoise-openssl](https://github.com/tinskip/infnoise-openssl) (dormant since 2020); this provider shares no code with it.

**Independent implementation.** This project is not affiliated with or endorsed by the upstream Infinite Noise TRNG project ([waywardgeek/infnoise](https://github.com/waywardgeek/infnoise)) or the vendor I bought it from (https://leetronics.de/en/shop/infinite-noise-trng/).

> **Alpha software** (current tag: `v0.0.1-alpha`).  The code passes its own test harness and sanitizer runs, but has not been independently audited.  Do not use this to seed production key material without your own review.  See [SECURITY.md](SECURITY.md) for the disclosure policy and [doc/TODO.txt](doc/TODO.txt) for the path to beta.

## Requirements

- **OpenSSL 3.x** (tested with 3.4+)
- **libinfnoise** and its dependency **libftdi1** (from the [infnoise](https://github.com/waywardgeek/infnoise) project)
- **Infinite Noise TRNG** USB device connected
- **GCC** with C11 support
- **pkg-config** (used by the Makefile to locate libcrypto and libftdi1)
- Linux (tested on Arch Linux; should work on any distro with the above)

### Arch Linux

```sh
# libftdi1 is in the official repos
pacman -S libftdi openssl pkgconf

# infnoise / libinfnoise from AUR or manual build
# See https://github.com/waywardgeek/infnoise/tree/master/software
```

### Debian / Ubuntu

```sh
apt install libftdi1-dev libssl-dev pkg-config
# Build libinfnoise from source — see upstream README
```

## Building

```sh
make
```

This produces `infnoise.so` — a hardened shared library (Full RELRO, stack canary, CET/IBT, NX, PIE, stripped).

To install into the OpenSSL modules directory (typically `/usr/lib/ossl-modules/`):

```sh
sudo make install
```

Optional — build and install the manpage (requires `pandoc`):

```sh
make man
sudo make install-man   # → /usr/share/man/man7/OSSL_PROVIDER-infnoise.7
man OSSL_PROVIDER-infnoise
```

## Configuration

Copy or symlink `conf/infnoise-provider.cnf` and point OpenSSL at it:

```sh
export OPENSSL_CONF=conf/infnoise-provider.cnf
```

Or append the relevant sections to your system `/etc/ssl/openssl.cnf`:

```ini
[provider_sect]
default = default_sect
infnoise = infnoise_sect

[default_sect]
activate = 1

[infnoise_sect]
module = /usr/lib/ossl-modules/infnoise.so
activate = 1

[random_sect]
seed = infnoise
```

## Verifying the hardware

Confirm the TRNG is detected:

```sh
# List USB devices — should show "13-37.org / Infinite Noise TRNG"
lsusb | grep 0403:6015

# Quick test with the infnoise CLI (from upstream package)
infnoise --list-devices
```

Verify the provider loads and generates entropy:

```sh
# Check provider is recognized
openssl list -providers -provider-path /usr/lib/ossl-modules -provider infnoise

# Generate random bytes through the provider
OPENSSL_CONF=conf/infnoise-provider.cnf openssl rand -hex 64

# Statistical quality check (requires ent)
OPENSSL_CONF=conf/infnoise-provider.cnf openssl rand 1000000 | ent
```

Generate keys using hardware entropy:

```sh
OPENSSL_CONF=conf/infnoise-provider.cnf openssl genrsa 4096
OPENSSL_CONF=conf/infnoise-provider.cnf openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
```

## Testing

The test harness runs 27 tests across 5 layers (hardware, provider API, integration, statistical, memory safety) plus sanitizer, valgrind, static-analysis, and soak targets.  See [doc/Testing.txt](doc/Testing.txt) for invocations and the per-layer breakdown.

## USB permissions

By default, the FTDI device requires root access.  To use without root, create a udev rule:

```sh
# /etc/udev/rules.d/75-infnoise.rules
SUBSYSTEM=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6015", \
  GROUP="plugdev", MODE="0664", TAG+="uaccess"
```

Then reload udev and add your user to the group:

```sh
sudo udevadm control --reload-rules
sudo usermod -aG plugdev $USER
# Log out and back in for group change to take effect
```

## Project layout

```
infnoise-provider/
  src/infnoise_prov.c        Provider implementation
  test/test_infnoise_prov.c  Test harness (27 tests)
  test/test_infnoise_soak.c  24-hour soak: drives EVP_RAND through every
                             spill-buffer phase, cycles instantiate/
                             uninstantiate, tracks RSS for leaks, dumps
                             rolling samples for ent/rngtest/dieharder
  conf/infnoise-provider.cnf OpenSSL configuration
  conf/openssl.supp          Valgrind suppressions
  doc/ARCHITECTURE.txt       Design decisions and security analysis
  doc/Build_Security.txt     Binary hardening + runtime security properties
  doc/CONTRIBUTING.txt       Contribution guidelines
  doc/OSSL_PROVIDER-infnoise.7.md
                             Pandoc source for the section-7 manpage
  doc/Testing.txt            Test harness layers and invocations
  doc/TODO.txt               Deferred work toward beta
  .github/                   Issue and pull-request templates
  .editorconfig              Editor style rules
  SECURITY.md                Vulnerability disclosure policy
  CODE_OF_CONDUCT.md         Contributor Covenant 2.1
  Makefile                   Build system
  LICENSE                    GPL-2.0-or-later
```

## Security

Full binary hardening (RELRO, stack canary, CET/IBT, NX, PIE, FORTIFY_SOURCE=3, stripped), entropy-buffer cleansing on all paths, `mlock`'d seed buffers, bounded request sizes, and thread-safe dispatch.  See [doc/Build_Security.txt](doc/Build_Security.txt) for the full list and [doc/ARCHITECTURE.txt](doc/ARCHITECTURE.txt) for the design rationale.

## Known limitations

- **Single instance per device.** Only one process can open an FTDI device at a time; the provider serializes its own context via `CRYPTO_RWLOCK`.  If built against a patched libinfnoise that holds state per-context (detected at compile time), the library-level constraint disappears but USB exclusion still applies.
- **`exit(1)` on health check failure** with unpatched libinfnoise (`>20` sequential identical bits).  Upstream behavior the provider cannot intercept.  Fixed upstream in [waywardgeek/infnoise@527ff2a](https://github.com/waywardgeek/infnoise/commit/527ff2a) (Matthew Brooks).
- **Throughput ~50 KB/s** (USB bulk transfer speed bound).  Suitable for seeding DRBGs and key generation; not suitable for bulk random data production.

## Contributing

Patches, bug reports, and feature proposals are welcome.  See [doc/CONTRIBUTING.txt](doc/CONTRIBUTING.txt) for style, build / test expectations, and the security invariants that any change must preserve.  All participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

For suspected vulnerabilities, please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

GPL-2.0-or-later.  See [LICENSE](LICENSE) for details.

This provider links OpenSSL (Apache 2.0).  Pure GPL-2.0 is incompatible with Apache 2.0; the "or later" clause elevates the effective license to GPL-3.0 at distribution time, which is explicitly Apache-2.0-compatible.

Copyright (C) 2025-2026 Avinash H. Duduskar.
