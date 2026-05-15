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
require_file packaging/systemd/merovingian.service
require_file packaging/openrc/merovingian
require_file packaging/rc.d/merovingian
require_file docs/progress.md
require_file docs/protocol-coverage.md
require_file docs/01-production-readiness.md
require_file docs/security-review-checklist.md
require_file scripts/build-linux.sh
require_file scripts/build-bsd.sh
require_file scripts/build-wsl.ps1
require_file scripts/wsl-setup.sh

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

exit "$status"
