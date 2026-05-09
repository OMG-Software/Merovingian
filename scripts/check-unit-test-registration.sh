#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=${1:-.}
cd "$repo_root"

actual=$(find tests/unit -maxdepth 1 -type f -name 'test_*.cpp' -printf 'unit/%f\n' | sort)
registered=$(sed -n "s/^[[:space:]]*'\(unit\/test_[^']*\.cpp\)'.*/\1/p" tests/meson.build | sort)

missing=$(comm -23 /tmp/actual-unit-tests.$$ /tmp/registered-unit-tests.$$ 2>/dev/null || true)
extra=$(comm -13 /tmp/actual-unit-tests.$$ /tmp/registered-unit-tests.$$ 2>/dev/null || true)

printf '%s\n' "$actual" > /tmp/actual-unit-tests.$$
printf '%s\n' "$registered" > /tmp/registered-unit-tests.$$

missing=$(comm -23 /tmp/actual-unit-tests.$$ /tmp/registered-unit-tests.$$)
extra=$(comm -13 /tmp/actual-unit-tests.$$ /tmp/registered-unit-tests.$$)

rm -f /tmp/actual-unit-tests.$$ /tmp/registered-unit-tests.$$

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
