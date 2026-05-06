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
# Verify (in another terminal while this runs):
#   ls /sys/bus/usb/devices/*/manufacturer  # finds the FTDI handle
#   strace -p $(pidof python3) -e openat 2>&1 | grep -i ttyUSB

import sys

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
