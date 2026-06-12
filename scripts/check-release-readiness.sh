#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

status=0

fail() {
    printf 'release readiness failure: %s\n' "$1" >&2
    status=1
}

require_file() {
    [ -f "$1" ] || fail "missing required file: $1"
}

require_file Dockerfile
require_file packaging/deb/control
require_file packaging/rpm/merovingian.spec
require_file packaging/freebsd/+MANIFEST
require_file packaging/openbsd/DESCR
require_file packaging/openbsd/PLIST
require_file packaging/netbsd/Makefile
require_file packaging/systemd/merovingian.service
require_file packaging/openrc/merovingian
require_file packaging/rc.d/merovingian
require_file docs/todos/priorities.md
require_file docs/todos/production-milestone.md
require_file docs/release-process.md
require_file docs/security-review-checklist.md
require_file docs/build-warning-policy.md
require_file docs/observability-audit.md
require_file docs/trust-safety.md
require_file docs/hardening-alpha-exceptions.md
require_file docs/dependencies/index.md
require_file docs/dependencies/catch2.md
require_file docs/dependencies/libcurl.md
require_file docs/dependencies/libsodium.md
require_file docs/dependencies/openssl.md
require_file docs/dependencies/postgresql-libpq.md
require_file docs/dependencies/sqlite.md
require_file docs/dependencies/yyjson.md
require_file scripts/build-linux.sh
require_file scripts/build-static-linux.sh
require_file scripts/build-bsd.sh
require_file scripts/build-wsl.ps1
require_file scripts/wsl-setup.sh
require_file scripts/tool-shims/make
require_file .github/workflows/release.yml
require_file .github/workflows/secret-scan.yml
require_file .github/workflows/dependency-vulnerability-triage.yml
require_file .github/workflows/sbom.yml
require_file .github/dependency-review-config.yml
require_file .gitleaks.toml
require_file subprojects/curl.wrap
require_file subprojects/sqlite3.wrap
require_file subprojects/yyjson.wrap
require_file subprojects/catch2.wrap
require_file subprojects/packagefiles/curl/meson.build

if grep -R "password-hash:v1" src include >/dev/null 2>&1; then
    fail "production sources still contain legacy password-hash:v1"
fi

if grep -R "token-hash:v1" src include >/dev/null 2>&1; then
    fail "production sources still contain legacy token-hash:v1"
fi

if grep -R -E "fnv1a64|stable_hash" src/homeserver src/auth >/dev/null 2>&1; then
    fail "auth production sources still contain non-cryptographic hashing"
fi

if grep -R -E "sha256_initial|sha256_round_constants|sha256_hex" src/media >/dev/null 2>&1; then
    fail "media production sources still contain project-local hashing primitives"
fi

if grep -q "Early Phase 1 bootstrap implementation" README.md; then
    fail "README status still describes the project as early Phase 1"
fi

# Signed release infrastructure: the release workflow must produce SLSA
# provenance attestations and SHA-256 checksums for every published artifact.
if ! grep -qF "attest-build-provenance" .github/workflows/release.yml; then
    fail "release.yml does not reference actions/attest-build-provenance (SLSA provenance is not attached)"
fi

if ! grep -qF "attestations: write" .github/workflows/release.yml; then
    fail "release.yml job is missing 'attestations: write' permission required for SLSA attestation"
fi

if ! grep -qF "sha256sum" .github/workflows/release.yml; then
    fail "release.yml does not generate sha256sum checksums for Linux release artifacts"
fi

if ! grep -qF "sha256 -q" .github/workflows/release.yml; then
    fail "release.yml does not generate sha256 checksums for FreeBSD release artifacts"
fi

exit "$status"
