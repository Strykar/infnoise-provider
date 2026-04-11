# infnoise-provider

OpenSSL 3.x provider for the [Infinite Noise TRNG](https://github.com/leetronics/infnoise) hardware random number generator.

This provider registers an `OSSL_OP_RAND` seed source backed by the Infinite Noise TRNG, a USB true random number generator based on modular entropy multiplication.  When configured as the DRBG seed source, all OpenSSL cryptographic operations (key generation, signatures, TLS handshakes) are seeded with hardware entropy.

Written from scratch for the OpenSSL 3.x Provider API.  A legacy ENGINE implementation exists at [tinskip/infnoise-openssl](https://github.com/tinskip/infnoise-openssl) (appears dormant since 2020).

## Requirements

- **OpenSSL 3.x** (tested with 3.4+)
- **libinfnoise** and its dependency **libftdi1** (from the [infnoise](https://github.com/leetronics/infnoise) project)
- **Infinite Noise TRNG** USB device connected
- **GCC** with C11 support
- Linux (tested on Arch Linux; should work on any distro with the above)

### Arch Linux

```sh
# libftdi1 is in the official repos
pacman -S libftdi openssl

# infnoise / libinfnoise from AUR or manual build
# See https://github.com/leetronics/infnoise/tree/master/software
```

### Debian / Ubuntu

```sh
apt install libftdi1-dev libssl-dev
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

The test harness runs 27 tests across 5 layers.  The TRNG must be connected for hardware tests.

```sh
# Standard test run
make test

# AddressSanitizer (buffer overflows, use-after-free, leaks)
make test-asan

# UndefinedBehaviorSanitizer (signed overflow, null deref, etc.)
make test-ubsan

# Valgrind (requires glibc debug symbols on Arch)
make test-valgrind

# Static analysis (cppcheck + gcc -fanalyzer)
make lint
```

### Test layers

| Layer | Tests | What it covers |
|-------|-------|----------------|
| 1. Hardware | 4 | USB detection, init/deinit, raw reads |
| 2a. Provider API (no HW) | 6 | Load, params, fetch, gettable, state, reload cycles |
| 2b. Provider API (HW) | 6 | Lifecycle, ctx params, locking, strength, sizes, reseed |
| 3. Integration | 3 | RAND_bytes, RSA-2048 keygen, EC P-256 keygen |
| 4. Statistical | 4 | NIST monobit, chi-squared, runs, two-sample independence |
| 5. Memory safety | 4 | Context churn, instantiate churn, boundary sizes, zero-length |

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
  conf/infnoise-provider.cnf OpenSSL configuration
  conf/openssl.supp          Valgrind suppressions
  doc/ARCHITECTURE.txt        Design decisions and security analysis
  Makefile                    Build system
  LICENSE                     LGPL-3.0
```

## Security

- Full binary hardening: RELRO, stack canary, CET/IBT, NX, PIE, FORTIFY_SOURCE=3, stripped
- All entropy buffers cleansed after use (`OPENSSL_cleanse`)
- Partial output cleansed on error (no stale data returned to caller)
- Thread-safe via OpenSSL's CRYPTO_RWLOCK dispatch
- DoS prevention: 1 MiB max request, 100 zero-read retry limit
- Seed buffers in `mlock`'d pages (`OPENSSL_secure_malloc`)
- Constant-time zeroization verification (`CRYPTO_memcmp`)

See [doc/ARCHITECTURE.txt](doc/ARCHITECTURE.txt) for the full adversarial review and design rationale.

## Known limitations

- **Single instance only.** libinfnoise uses global state for its Keccak sponge and health checker.  Only one provider context can be active at a time.  In practice, the FTDI USB exclusion enforces this (only one process can open the device).
- **libinfnoise calls `exit(1)` on health check failure** (>20 sequential identical bits).  This is an upstream issue that terminates the host process.  There is no way to intercept this from the provider.
- **Throughput is ~50 KB/s** (limited by USB bulk transfer speed).  Sufficient for seeding DRBGs and key generation; not suitable for bulk random data production.

## License

LGPL-3.0-or-later.  See [LICENSE](LICENSE) for details.

By Avinash H. Duduskar.
