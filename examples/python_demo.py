#!/usr/bin/env python3
# Copyright (C) 2025-2026 Avinash H. Duduskar.
# SPDX-License-Identifier: GPL-2.0-or-later
# https://github.com/Strykar/infnoise-provider
#
# Demonstrate the Infnoise TRNG provider seeding OpenSSL-backed
# operations from Python.
#
# How it works:
#   The 'cryptography' package calls into libcrypto for RSA keygen,
#   ECDH, AES-GCM, etc.  When OPENSSL_CONF points at a config that
#   loads the infnoise provider as the seed source, libcrypto's
#   default DRBG pulls its seed from the device.  No code change in
#   the Python script is needed: the provider plugs in below the API.
#
# Run:
#   OPENSSL_CONF=/path/to/infnoise-provider.cnf python3 python_demo.py
#
# Two pre-flight checks fail closed before any keygen happens:
#   1. OPENSSL_CONF is set (otherwise the provider was never loaded).
#   2. libcrypto reports the infnoise provider is active (otherwise
#      the keygen would silently fall back to the default RNG).
#
# Caveat: if the 'cryptography' package was pip-installed from a
# manylinux wheel, it bundles its own libcrypto.  The pre-flight
# check below probes the system libcrypto via the openssl CLI; on
# distros where cryptography links against the same system libcrypto
# (Arch python-cryptography, Debian python3-cryptography) the two
# match.  With a pip wheel they may not, and the check can pass while
# cryptography's own libctx still lacks the provider.

import os
import subprocess
import sys


def preflight() -> None:
    if "OPENSSL_CONF" not in os.environ:
        sys.exit("FAIL: OPENSSL_CONF is unset; see README for setup.")

    try:
        out = subprocess.run(
            ["openssl", "list", "-providers"],
            check=True, capture_output=True, text=True,
        ).stdout
    except FileNotFoundError:
        sys.exit("FAIL: openssl CLI not on PATH.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"FAIL: openssl list -providers exited {e.returncode}:\n{e.stderr}")

    if "infnoise" not in out:
        sys.exit("FAIL: 'infnoise' provider not loaded.  Check that\n"
                 f"  OPENSSL_CONF={os.environ['OPENSSL_CONF']}\n"
                 "points at a config that loads it, and that the\n"
                 "provider .so is installed under OpenSSL's modules\n"
                 "directory (openssl version -m).")


preflight()

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEY_SIZE = 2048

print(f"generating an RSA-{KEY_SIZE} key via OpenSSL ...", file=sys.stderr)
key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
sys.stdout.buffer.write(pem)
print(f"ok, {len(pem)} bytes of PKCS#8 PEM written", file=sys.stderr)
