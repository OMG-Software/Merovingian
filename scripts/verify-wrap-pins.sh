#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

status=0

fail() {
    printf 'wrap-pin failure: %s\n' "$1" >&2
    status=1
}

for wrap_path in subprojects/*.wrap; do
    [ -f "$wrap_path" ] || continue
    wrap_name=$(basename "$wrap_path" .wrap)

    # GIVEN every committed wrap is part of the dependency lockfile.
    # WHEN the build resolves a dependency.
    # THEN only immutable [wrap-file] entries with SHA-256 hashes are allowed.
    if ! grep -qE '^\[wrap-file\]' "$wrap_path"; then
        fail "${wrap_name}.wrap is not a [wrap-file] entry"
    fi

    if ! grep -qE '^source_hash[[:space:]]*=' "$wrap_path"; then
        fail "${wrap_name}.wrap is missing source_hash"
    fi

    # Hash must be a 64-character lowercase hex string.
    if ! grep -qE '^source_hash[[:space:]]*=[[:space:]]*[0-9a-f]{64}[[:space:]]*$' "$wrap_path"; then
        fail "${wrap_name}.wrap source_hash is not a 64-character lowercase hex value"
    fi

    # Git wraps are forbidden because tags are mutable and shallow clones are
    # non-deterministic.
    if grep -qE '^\[wrap-git\]' "$wrap_path"; then
        fail "${wrap_name}.wrap uses a forbidden [wrap-git] entry"
    fi
done

exit "$status"
