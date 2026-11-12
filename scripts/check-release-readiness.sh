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
require_file docs/todos/production-milestone.md
require_file docs/release-process.md
require_file docs/security-review-checklist.md
require_file docs/build-warning-policy.md
require_file docs/observability-audit.md
require_file docs/trust-safety.md
require_file docs/dependencies/index.md
require_file docs/dependencies/catch2.md
require_file docs/dependencies/libcurl.md
require_file docs/dependencies/libsodium.md
require_file docs/dependencies/openssl.md
require_file docs/dependencies/postgresql-libpq.md
require_file docs/dependencies/sqlite.md
require_file docs/dependencies/yyjson.md
require_file docs/dependencies/licenses.md
require_file scripts/generate-license-summary.py
require_file scripts/generate_sbom.py
require_file scripts/stage-release-tarball.sh
require_file scripts/verify-wrap-pins.sh
require_file scripts/build-linux.sh
require_file scripts/build-static-linux.sh
require_file scripts/build-bsd.sh
require_file scripts/build-wsl.ps1
require_file scripts/wsl-setup.sh
require_file scripts/tool-shims/make
require_file .github/workflows/release.yml
require_file .github/workflows/secret-scan.yml
require_file .github/workflows/dependency-vulnerability-triage.yml
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

# Signed release infrastructure (ADR-0652): packages.yml builds, attests, checksums
# and signs every published package, for the rolling `latest` release and, called
# by release.yml, for every tag. release.yml must call it with the attestation
# permission and the secrets its signing job needs.
if ! grep -qF "uses: actions/attest-build-provenance" .github/workflows/packages.yml; then
    fail "packages.yml does not use actions/attest-build-provenance (SLSA provenance is not attached)"
fi

if ! grep -qF "attestations: write" .github/workflows/packages.yml; then
    fail "packages.yml is missing the 'attestations: write' permission required for SLSA attestation"
fi

if ! grep -qF "sha256sum packages/* > packages/SHA256SUMS" .github/workflows/packages.yml; then
    fail "packages.yml does not write SHA256SUMS over the published packages"
fi

if ! grep -qF "uses: ./.github/workflows/packages.yml" .github/workflows/release.yml; then
    fail "release.yml does not build its packages with packages.yml"
fi
if ! grep -qF "attestations: write" .github/workflows/release.yml; then
    fail "release.yml does not grant packages.yml the 'attestations: write' permission"
fi
if ! grep -qF "secrets: inherit" .github/workflows/release.yml; then
    fail "release.yml does not pass packages.yml the secrets its signing job needs"
fi

# GPG release signatures: packages.yml, which stages both `latest` and every tag,
# must call the reusable signing workflow.
if ! grep -qF "./.github/workflows/sign-artifacts.yml" .github/workflows/packages.yml; then
    fail "packages.yml does not call the GPG signing reusable workflow"
fi

# Dependency pinning: every wrap must be an immutable [wrap-file] with a
# SHA-256 source_hash.
if ! sh scripts/verify-wrap-pins.sh; then
    fail "dependency wraps are not pinned as immutable [wrap-file] entries"
fi

# License review: the human-readable and machine-readable summaries must be
# derivable from the same source of truth and must not be empty.
if ! python3 scripts/generate-license-summary.py /tmp/merovingian.licenses.json; then
    fail "license summary could not be generated from docs/dependencies/licenses.md"
fi
if ! [ -s /tmp/merovingian.licenses.json ]; then
    fail "generated license summary is empty"
fi

# SBOM (ADR-0598): packages.yml attaches it to `latest` and to every tag
# (ADR-0652), and it must generate from licenses.md and the wraps. A fixed commit
# and creation time keep this check free of git, which the BSD release VMs may
# not have a history for.
if ! grep -qF "scripts/generate_sbom.py" .github/workflows/packages.yml; then
    fail "packages.yml does not generate the SBOM with scripts/generate_sbom.py"
fi
sbom_dir=$(mktemp -d)
trap 'rm -rf "$sbom_dir"' EXIT
if ! SOURCE_DATE_EPOCH=0 python3 scripts/generate_sbom.py         --spdx "${sbom_dir}/merovingian.spdx.json"         --cyclonedx "${sbom_dir}/merovingian.cdx.json"         --commit 0000000000000000000000000000000000000000; then
    fail "SBOM could not be generated from docs/dependencies/licenses.md and subprojects/*.wrap"
fi
rm -rf "$sbom_dir"

exit "$status"
