#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

repo_root=${1:-.}
cd "$repo_root"

status=0

for file in tests/unit/test_*.cpp; do
    case "$file" in
        tests/unit/test_main.cpp)
            continue
            ;;
    esac

    if grep -q 'TEST_CASE' "$file"; then
        printf '%s\n' "$file uses TEST_CASE; use Catch2 SCENARIO/GIVEN/WHEN/THEN" >&2
        status=1
    fi

    if grep -q '// Given\|// When\|// Then' "$file"; then
        printf '%s\n' "$file uses comment-only Given/When/Then markers; use Catch2 macros" >&2
        status=1
    fi

    if ! grep -q 'SCENARIO' "$file" || ! grep -q 'GIVEN' "$file" || ! grep -q 'WHEN' "$file" || ! grep -q 'THEN' "$file"; then
        printf '%s\n' "$file is missing Catch2 BDD macros" >&2
        status=1
    fi
done

exit "$status"
