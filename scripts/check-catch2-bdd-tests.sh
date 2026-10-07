#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Rejects unit test files that are not written in Catch2 BDD style: TEST_CASE,
# comment-only Given/When/Then markers, or any of SCENARIO/GIVEN/WHEN/THEN
# missing. tests/unit/test_main.cpp is exempt.
#
# One awk process reads every file once. Started per file and per rule, grep
# ran ~1,300 processes and the gate timed out on the OpenBSD CI VM.

set -eu

repo_root=${1:-.}
cd "$repo_root"

set --
for file in tests/unit/test_*.cpp; do
    if [ -f "$file" ] && [ "$file" != tests/unit/test_main.cpp ]; then
        set -- "$@" "$file"
    fi
done
if [ "$#" -eq 0 ]; then
    exit 0
fi

# Files are reported in argument order, each with its messages in the order
# the rules are listed; an empty file has no records and is caught as missing
# every macro.
exec awk '
    /TEST_CASE/ { test_case[FILENAME] = 1 }
    /\/\/ Given|\/\/ When|\/\/ Then/ { comment_markers[FILENAME] = 1 }
    /SCENARIO/ { scenario[FILENAME] = 1 }
    /GIVEN/ { given[FILENAME] = 1 }
    /WHEN/ { when_[FILENAME] = 1 }
    /THEN/ { then_[FILENAME] = 1 }
    END {
        status = 0
        for (i = 1; i < ARGC; i++) {
            file = ARGV[i]
            if (file in test_case) {
                print file " uses TEST_CASE; use Catch2 SCENARIO/GIVEN/WHEN/THEN" > "/dev/stderr"
                status = 1
            }
            if (file in comment_markers) {
                print file " uses comment-only Given/When/Then markers; use Catch2 macros" > "/dev/stderr"
                status = 1
            }
            if (!(file in scenario) || !(file in given) || !(file in when_) || !(file in then_)) {
                print file " is missing Catch2 BDD macros" > "/dev/stderr"
                status = 1
            }
        }
        exit status
    }
' "$@"
