% OSSL_PROVIDER-infnoise(7) | OpenSSL providers

NAME
====

OSSL_PROVIDER-infnoise - Infinite Noise TRNG seed source for OpenSSL 3.x


DESCRIPTION
===========

The *infnoise* provider registers an `OSSL_OP_RAND` algorithm backed by
the Infinite Noise TRNG, a USB hardware random number generator based
on modular entropy multiplication.  Configured as the DRBG seed source
in `openssl.cnf`, every OpenSSL cryptographic operation (key generation,
signatures, TLS handshakes) is seeded with hardware entropy.

The provider is loaded via configuration directives in `openssl.cnf`
(see **CONFIGURATION** below) or directly by an application through
`OSSL_PROVIDER_load(3)`.

Throughput is bounded by USB bulk-transfer speed at roughly 50 KiB/s.
The provider is intended as a seed source for DRBGs and for key
generation, not for bulk random data production.


Properties
----------

Implementations can be selected with the property filter `provider=infnoise`
via `EVP_RAND_fetch(3)` and related APIs.


OPERATIONS AND ALGORITHMS
=========================

Random Number Generation
------------------------

* `infnoise`

  A live hardware entropy source.  Advertised parameters:

  | Parameter                 | Type      | Value                        |
  |---------------------------|-----------|------------------------------|
  | `state`                   | integer   | UNINITIALISED / READY / ERROR|
  | `strength`                | unsigned  | 256 bits                     |
  | `max_request`             | size_t    | 1048576 (1 MiB)              |

  Requests exceeding `max_request` or `strength` are rejected.

  `reseed` is a no-op: a live TRNG cannot meaningfully be reseeded.
  `verify_zeroization` is supported and uses a constant-time compare.
  Locking is enabled via the standard `enable_locking` / `lock` /
  `unlock` dispatch entries; a single context is serialised with
  `CRYPTO_RWLOCK`.


CONFIGURATION
=============

The following fragment loads the provider and wires it as the DRBG
seed source:

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
random    = random_sect

[provider_sect]
default  = default_sect
infnoise = infnoise_sect

[default_sect]
activate = 1

[infnoise_sect]
module   = /usr/lib/ossl-modules/infnoise.so
activate = 1

[random_sect]
seed = infnoise
```

A ready-to-use file is shipped as `conf/infnoise-provider.cnf` in the
source tree.


ENVIRONMENT
===========

`OPENSSL_CONF`
:   Path to the configuration file that loads the provider.  When set,
    takes precedence over the system `openssl.cnf`.

`OPENSSL_MODULES`
:   Directory searched for provider modules when the `module` path in
    the configuration is not absolute.  Defaults to the OpenSSL
    install's modules directory (typically `/usr/lib/ossl-modules`).


EXAMPLES
========

Confirm the provider loads:

```
openssl list -providers -provider-path /usr/lib/ossl-modules \
        -provider infnoise
```

Generate random bytes through the provider:

```
OPENSSL_CONF=conf/infnoise-provider.cnf openssl rand -hex 64
```

Entropy sanity check (requires `ent`):

```
OPENSSL_CONF=conf/infnoise-provider.cnf openssl rand 1000000 | ent
```

Hardware-seeded key generation:

```
OPENSSL_CONF=conf/infnoise-provider.cnf openssl genrsa 4096
OPENSSL_CONF=conf/infnoise-provider.cnf \
        openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256
```


FILES
=====

`/usr/lib/ossl-modules/infnoise.so`
:   The provider shared object (installed by `make install`).

`/etc/ssl/openssl.cnf`
:   System OpenSSL configuration; append the sections from
    **CONFIGURATION** to activate the provider system-wide.

`conf/infnoise-provider.cnf`
:   Standalone configuration file shipped with the source for use via
    `OPENSSL_CONF`.


NOTES
=====

Alpha status
:   This provider is alpha software (v0.0.x).  It has not been
    independently audited.  See `SECURITY.md` in the source tree for
    the disclosure policy.

Single-instance-per-device
:   Only one process may hold an FTDI device open at a time.  Running
    the provider concurrently with an `infnoise` daemon or another
    application using the same device will fail at `instantiate`.

Kernel driver interference
:   The `ftdi_sio` kernel driver claims the FTDI interface by default.
    Unbind it (or configure a udev rule that does so automatically)
    before using the device through libftdi.  The most common cause of
    "device not found" is `ftdi_sio` holding the interface.

USB permissions
:   Non-root callers need access to the FTDI device.  A minimal udev
    rule:

        SUBSYSTEM=="usb", ATTRS{idVendor}=="0403", \
            ATTRS{idProduct}=="6015", \
            GROUP="plugdev", MODE="0664", TAG+="uaccess"

Upstream health-check behaviour
:   With unpatched libinfnoise, the library calls `exit(1)` on certain
    health-check failures.  The provider cannot intercept this.  Fixed
    upstream in waywardgeek/infnoise commit `527ff2a`.


SEE ALSO
========

`openssl(1)`, `config(5)`, `provider(7)`, `provider-rand(7)`,
`RAND_bytes(3)`, `EVP_RAND(3)`, `OSSL_PROVIDER-default(7)`, `infnoise(1)`


HISTORY
=======

The *infnoise* provider was introduced in v0.0.1-alpha.


COPYRIGHT
=========

Copyright (C) 2025-2026 Avinash H. Duduskar.

Licensed under the GNU General Public License version 2 or any later
version (SPDX: GPL-2.0-or-later).  See the `LICENSE` file in the
source tree for the full text.
