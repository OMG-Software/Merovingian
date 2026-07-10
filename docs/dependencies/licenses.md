# Dependency license compatibility

This document records the license of every third-party dependency that ships
with Merovingian binaries or is required to build them, and confirms each
license is compatible with Merovingian's `GPL-3.0-or-later` distribution.

## Direct dependencies

| Dependency | License | SPDX | Compatible with GPL-3.0-or-later | Notes |
| --- | --- | --- | --- | --- |
| LibSodium | ISC | `ISC` | Yes | Runtime cryptography; dynamically linked from the OS package. |
| OpenSSL | Apache-2.0 / OpenSSL-3.0 | `Apache-2.0` | Yes | Runtime TLS listener; dynamically linked from the OS package. |
| libcurl | curl license (MIT-like) | `curl` | Yes | Federation outbound HTTP client; dynamically linked from the OS package. |
| PostgreSQL libpq | PostgreSQL license | `PostgreSQL` | Yes | PostgreSQL client library; dynamically linked from the OS package. |
| SQLite | Public-domain dedication | `blessing` | Yes | Embedded database; statically linked from the pinned Meson wrap. |
| yyjson | MIT | `MIT` | Yes | Canonical JSON parser; statically linked from the pinned Meson wrap. |
| Catch2 | Boost Software License 1.0 | `BSL-1.0` | Yes | Test-only framework; never linked into production targets. |

## Transitive image codec dependencies

The thumbnail worker uses OS-provided image libraries. They are loaded in a
sandboxed subprocess but are still required to build the feature.

| Dependency | License | SPDX | Compatible with GPL-3.0-or-later | Notes |
| --- | --- | --- | --- | --- |
| libpng | libpng license | `Libpng` | Yes | PNG thumbnail decoding. |
| libjpeg-turbo | BSD-3-Clause / IJG | `BSD-3-Clause` | Yes | JPEG thumbnail decoding. |

## Policy

- Runtime security and database libraries are resolved from OS packages so the
  distribution's security update path applies.
- Source-pinned dependencies use Meson `[wrap-file]` entries with SHA-256
  hashes. Every wrap is recorded in the review documents under this directory.
- Test-only dependencies must use a license compatible with the test suite and
  must not be linked into production binaries.
- Any new dependency must be added to this table before the corresponding code
  or wrap is merged, and must be covered by the `dependency-review-action`
  license gate.

## Verification

The GitHub Actions `dependency-review-action` is enabled with `license-check:
true`. Release readiness is gated by `scripts/check-release-readiness.sh`, which
requires this file and the per-dependency review notes to exist.
