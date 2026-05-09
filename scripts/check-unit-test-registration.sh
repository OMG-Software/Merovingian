#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=${1:-.}
cd "$repo_root"

actual_file=$(mktemp)
registered_file=$(mktemp)
trap 'rm -f "$actual_file" "$registered_file"' EXIT HUP INT TERM

find tests/unit -maxdepth 1 -type f -name 'test_*.cpp' -printf 'unit/%f\n' | sort > "$actual_file"
sed -n "s/^[[:space:]]*'\(unit\/test_[^']*\.cpp\)'.*/\1/p" tests/meson.build | sort > "$registered_file"

missing=$(comm -23 "$actual_file" "$registered_file")
extra=$(comm -13 "$actual_file" "$registered_file")

if [ -n "$missing" ]; then
    printf '%s\n' 'Unit tests present on disk but missing from tests/meson.build:' >&2
    printf '%s\n' "$missing" >&2
    exit 1
fi

if [ -n "$extra" ]; then
    printf '%s\n' 'Unit tests listed in tests/meson.build but missing on disk:' >&2
    printf '%s\n' "$extra" >&2
    exit 1
fi
