#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=${1:-.}
cd "$repo_root"

actual_unit_file=$(mktemp)
registered_unit_file=$(mktemp)
actual_conformance_file=$(mktemp)
registered_conformance_file=$(mktemp)
trap 'rm -f "$actual_unit_file" "$registered_unit_file" "$actual_conformance_file" "$registered_conformance_file"' EXIT HUP INT TERM

find tests/unit -maxdepth 1 -type f -name 'test_*.cpp' -printf 'unit/%f\n' | sort > "$actual_unit_file"
sed -n "s/^[[:space:]]*'\(unit\/test_[^']*\.cpp\)'.*/\1/p" tests/meson.build | sort > "$registered_unit_file"

find tests/conformance -maxdepth 1 -type f -name 'test_*.cpp' -printf 'conformance/%f\n' | sort > "$actual_conformance_file"
sed -n "s/^[[:space:]]*'\(conformance\/test_[^']*\.cpp\)'.*/\1/p" tests/meson.build | sort > "$registered_conformance_file"

missing_unit=$(comm -23 "$actual_unit_file" "$registered_unit_file")
extra_unit=$(comm -13 "$actual_unit_file" "$registered_unit_file")
missing_conformance=$(comm -23 "$actual_conformance_file" "$registered_conformance_file")
extra_conformance=$(comm -13 "$actual_conformance_file" "$registered_conformance_file")

if [ -n "$missing_unit" ]; then
    printf '%s\n' 'Unit tests present on disk but missing from tests/meson.build:' >&2
    printf '%s\n' "$missing_unit" >&2
    exit 1
fi

if [ -n "$extra_unit" ]; then
    printf '%s\n' 'Unit tests listed in tests/meson.build but missing on disk:' >&2
    printf '%s\n' "$extra_unit" >&2
    exit 1
fi

if [ -n "$missing_conformance" ]; then
    printf '%s\n' 'Conformance tests present on disk but missing from tests/meson.build:' >&2
    printf '%s\n' "$missing_conformance" >&2
    exit 1
fi

if [ -n "$extra_conformance" ]; then
    printf '%s\n' 'Conformance tests listed in tests/meson.build but missing on disk:' >&2
    printf '%s\n' "$extra_conformance" >&2
    exit 1
fi
