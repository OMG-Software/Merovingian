#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Verify that the static Linux fallback tarball builds byte-for-byte
# reproducibly by building it twice in the same build directory path and
# comparing the resulting SHA-256 hashes.
set -eu

# Operate from the repository root regardless of where the script is invoked.
cd "$(dirname "$0")/.."

if ! tar --version 2>&1 | grep -q 'GNU tar'; then
    printf 'error: GNU tar is required for reproducible build verification\n' >&2
    exit 1
fi

# Use the commit author date as the deterministic SOURCE_DATE_EPOCH when running
# inside a git checkout. Outside a git repo (e.g. some CI container fallbacks) use
# a fixed value. The same value is used for both builds so compiler/linker-
# visible timestamps and tar metadata are identical.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%at 2>/dev/null || printf '0')"
    if ! [ "$SOURCE_DATE_EPOCH" -gt 0 ] 2>/dev/null; then
        SOURCE_DATE_EPOCH=0
    fi
fi
export SOURCE_DATE_EPOCH
printf 'SOURCE_DATE_EPOCH=%s\n' "$SOURCE_DATE_EPOCH"

# Use a fixed build directory path for both builds so absolute paths embedded in
# object files are identical.
BUILD_DIR="build-reproducible"
export BUILD_DIR

first_log="$(mktemp)"
second_log="$(mktemp)"
trap 'rm -f "$first_log" "$second_log"' EXIT

printf 'Running first static Linux build...\n'
sh scripts/build-static-linux.sh > "$first_log"
tarball_path="$(tail -n 1 "$first_log" | sed 's/Built static Linux fallback: //')"
if [ ! -f "$tarball_path" ]; then
    printf 'error: first build did not produce expected tarball %s\n' "$tarball_path" >&2
    exit 1
fi
first_hash="$(sha256sum "$tarball_path" | cut -d' ' -f1)"
first_copy="$(mktemp -u).tar.gz"
cp "$tarball_path" "$first_copy"
trap 'rm -f "$first_log" "$second_log" "$first_copy"' EXIT

printf 'First build hash:  %s  %s\n' "$first_hash" "$tarball_path"

printf 'Running second static Linux build...\n'
sh scripts/build-static-linux.sh > "$second_log"
tarball_path="$(tail -n 1 "$second_log" | sed 's/Built static Linux fallback: //')"
second_hash="$(sha256sum "$tarball_path" | cut -d' ' -f1)"

printf 'Second build hash: %s  %s\n' "$second_hash" "$tarball_path"

if [ "$first_hash" != "$second_hash" ]; then
    printf 'error: static Linux tarball is NOT reproducible\n' >&2
    printf 'first:  %s\n' "$first_hash" >&2
    printf 'second: %s\n' "$second_hash" >&2
    exit 1
fi

printf 'Static Linux fallback tarball is byte-for-byte reproducible: %s\n' "$first_hash"
