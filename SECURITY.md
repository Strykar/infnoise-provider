# Security Policy

## Status

This is alpha software (version 0.0.x).  No security guarantees are
offered.  Do not use it to seed production key material without
independent review.  See [docs/Security_Review.txt](docs/Security_Review.txt)
for the brief used to scope an external cryptographic review (gating
the first signed release).

## Reporting a vulnerability

Please report security issues **privately**, not via public GitHub
issues, public PRs, public Discord/IRC, or any other public forum.

Open a [private security advisory](https://github.com/Strykar/infnoise-provider/security/advisories/new)
on GitHub, or email the maintainer listed in the repository commit
history.  Include:

- A description of the issue and its impact.
- Steps to reproduce, or proof-of-concept code.
- OpenSSL version, libinfnoise version, and platform.
- Whether you intend to publish a writeup, and on what timeline.

We do not currently run a paid bug bounty programme, but credit
(opt-in) will be given in the resulting fix commit, advisory, and
CHANGELOG once releases begin.

## Triage and response timeline

We follow the OpenSSF coordinated-disclosure model:

1. **Acknowledge** within 2 weeks of the report (typically much sooner).
2. **Reproduce** the issue against current master and the most recent
   tagged release.  Inability to reproduce is communicated back with
   specific environment details we tried.
3. **Prioritise** based on impact: memory disclosure, entropy
   compromise, and code execution are P0; correctness or DoS bugs are
   P1; hardening recommendations are P2.
4. **Remediate** by writing a fix, a regression test, and (if
   applicable) a fuzz seed input under `fuzz/regressions/`.  Fix
   timelines: P0 within 30 days, P1 within 90 days, P2 best-effort.
5. **Coordinate disclosure** with the reporter on a date.  By default
   we follow a 90-day disclosure window from the acknowledgement,
   shortened or extended by mutual agreement.
6. **Verify with reporter** that the fix addresses the issue before
   the public advisory is published.

## Safe harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, data destruction, and service disruption.
- Limit testing to systems you own or are authorised to test.
- Give us reasonable time to remediate before public disclosure.

This is a single-maintainer project; we cannot compel third parties
(GitHub, CI providers, downstream packagers) to extend the same
guarantee.  Coordinate with them separately for testing infrastructure
they operate.

## Key / account compromise

If the maintainer's GitHub account or release-signing key is
compromised, see [docs/Governance.txt §4](docs/Governance.txt) for
the rotation and notification procedure.

## Scope

In scope:

- The provider source in `src/` and its dispatch surface.
- The build configuration affecting the shipped shared object.
- Secrets handling: cleanse paths, secure allocation, zeroization.
- The fuzz harness suite, TSan and alloc-failure tests, mock
  libinfnoise stub (insofar as a flaw in the harness could mask
  flaws in the provider).
- The CI workflows under `.github/workflows/` (insofar as a
  workflow flaw could let a malicious PR ship to a release).

Out of scope:

- Bugs in OpenSSL, libinfnoise, libftdi, libusb, or the kernel.
  Report those upstream; we'll backport mitigations if needed.
- Physical attacks on the TRNG hardware itself.
- Denial-of-service via USB disconnection or device removal.
- Build-time attacks requiring control of the maintainer's local
  development environment.
