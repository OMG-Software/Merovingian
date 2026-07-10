# Catch2 dependency review

This note records the dependency review for Catch2.

## Decision

Catch2 is accepted as the test framework. It is test-only and must not be linked
into production targets.

## Why it is needed

The project requires behavior-driven tests in GIVEN/WHEN/THEN style. Catch2
provides the `SCENARIO`, `GIVEN`, `WHEN`, and `THEN` macros used by unit and
integration coverage.

## Security boundary

- Catch2 is only referenced from `tests/`.
- Test registration is checked by `scripts/check-unit-test-registration.sh`.
- BDD macro usage is checked by `scripts/check-catch2-bdd-tests.sh`.
- Production Meson targets do not depend on Catch2.

## Maintenance and platform posture

Catch2 is available through supported Linux and BSD package managers. A wrap is
present for environments where the system package is not available. Fallback
builds disable Catch2's own upstream self-test executable so CI builds only the
Merovingian test targets and does not inherit upstream compiler compatibility
noise.

## License

Catch2 is released under the Boost Software License 1.0 (`SPDX: BSL-1.0`). It
is compatible with Merovingian's GPL-3.0-or-later distribution. Catch2 is a
test-only dependency and must never be linked into production targets.

## Current limitations

- Conformance and fuzz coverage still need to expand before production gating.
