# Security Policy

## Status

This is alpha software (version 0.0.x).  No security guarantees are
offered.  Do not use it to seed production key material without
independent review.

## Reporting a vulnerability

Please report security issues privately, not via public GitHub issues.

Open a [private security advisory](https://github.com/Strykar/infnoise-provider/security/advisories/new)
on GitHub, or email the maintainer listed in the repository commit
history.  Include:

- A description of the issue and its impact.
- Steps to reproduce, or proof-of-concept code.
- OpenSSL version, libinfnoise version, and platform.

Expect an acknowledgement within two weeks.  Fix timelines depend on
severity and complexity; we will coordinate a disclosure date with you.

## Scope

In scope:

- The provider source in `src/` and its dispatch surface.
- The build configuration affecting the shipped shared object.
- Secrets handling: cleanse paths, secure allocation, zeroization.

Out of scope:

- Bugs in OpenSSL, libinfnoise, libftdi, or the kernel.
- Physical attacks on the TRNG hardware itself.
- Denial-of-service via USB disconnection.
