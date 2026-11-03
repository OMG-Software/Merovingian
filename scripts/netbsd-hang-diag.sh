#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# TEMPORARY, PR #554: find where the conformance binary hangs on NetBSD. A kill by meson's
# timeout leaves no stack, so run the binary here and take one from the live process. Always
# exits non-zero: a head carrying this script must not look green. Delete it with its CI lines.
set -u

binary=build/tests/merovingian-conformance-tests
export MEROVINGIAN_TEST_DISABLE_HARDENING=1

# Prints the stacks of process $1 from the live process and from a core, then removes it.
dump_stacks() {
    echo "::group::[netbsd-diag] live stacks of $1"
    gdb --batch -p "$1" -ex 'thread apply all bt' "$binary" 2>&1 || true
    echo "::endgroup::"
    kill -ABRT "$1" 2>/dev/null || true
    sleep 5
    kill -9 "$1" 2>/dev/null || true
    for core in $(find . -maxdepth 3 -name 'merovingian-conf*.core' 2>/dev/null); do
        echo "::group::[netbsd-diag] core stacks from $core"
        gdb --batch -ex 'thread apply all bt' "$binary" "$core" 2>&1 || true
        echo "::endgroup::"
    done
}

# Runs the binary with arguments $2... and returns 2 if it is still running after $1 seconds.
run_watched() {
    limit=$1
    shift
    "$binary" "$@" >"$diag_log" 2>&1 &
    pid=$!
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$limit" ]; then
            echo "[netbsd-diag] still running after ${limit}s: $*"
            tail -n 5 "$diag_log" | cut -c1-200
            dump_stacks "$pid"
            return 2
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "$pid"
    status=$?
    echo "[netbsd-diag] finished in ${waited}s with status $status: $*"
    if [ "$status" -ne 0 ]; then
        tail -n 40 "$diag_log" | cut -c1-200
    fi
    return 0
}

ulimit -c unlimited || true
diag_log=$(mktemp)

# The scenario alone first: quick, and it says whether earlier scenarios matter.
runs=0
started=$(date +%s)
while [ $(($(date +%s) - started)) -lt 300 ]; do
    runs=$((runs + 1))
    if ! run_watched 120 "[omit_members]"; then
        echo "[netbsd-diag] the scenario alone hung on run $runs"
        exit 1
    fi
done
echo "[netbsd-diag] the scenario alone did not hang in $runs runs"

# Then the whole binary, in the order that hung. It takes under 600 s when healthy.
if ! run_watched 1200; then
    echo "[netbsd-diag] the whole binary hung"
    exit 1
fi
echo "[netbsd-diag] the whole binary did not hang"
exit 1
