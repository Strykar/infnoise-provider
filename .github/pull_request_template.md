<!--
Thank you for contributing.  Please read doc/CONTRIBUTING.txt before
opening a PR.  Remove sections that do not apply.
-->

## Summary

<!-- One or two sentences describing the change and its motivation. -->

## Related issue

<!-- e.g. Fixes #12, Refs #34.  For anything non-trivial, an issue
     should exist first per CONTRIBUTING.txt §2. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation only
- [ ] Refactor with no behavior change
- [ ] Build / tooling

## Checklist

- [ ] `make clean && make` succeeds with no new warnings.
- [ ] `make test` passes (hardware connected).
- [ ] `make test-asan` clean.
- [ ] `make test-ubsan` clean.
- [ ] `make lint` introduces no new findings.
- [ ] Appropriate soak run completed (`test-soak-short` minimum,
      `test-soak` for dispatch / security-invariant changes).
- [ ] doc/ARCHITECTURE.txt updated if design changes.
- [ ] README.md updated if user-visible behavior changes.
- [ ] Commits rebased onto current master; no merge commits.
- [ ] New source files carry an SPDX-License-Identifier header.

## Security invariants

<!-- Does this patch touch any invariant from doc/ARCHITECTURE.txt §5?
     If so, explain how the invariant is preserved. -->

## Notes for reviewers

<!-- Anything non-obvious: trade-offs taken, alternatives rejected,
     follow-ups deferred. -->
