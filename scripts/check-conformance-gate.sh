#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Explicit conformance capability gate. Run after a full build to verify
# that all Matrix v1.18 conformance tests pass before continuing.

set -eu

builddir="${1:-build}"

if [ ! -d "$builddir" ]; then
    printf 'conformance gate: build directory not found: %s\n' "$builddir" >&2
    exit 1
fi

meson test -C "$builddir" conformance-tests --print-errorlogs
