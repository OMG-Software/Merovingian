#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# TEMPORARY, PR #554: find where the conformance binary hangs on NetBSD. A kill by meson's
# timeout leaves no stack, and gdb attaching to the hung process never returned, so this asks the
# kernel first, then takes a core and reads that. Every step has a time limit. Always exits
# non-zero: a head carrying this script must not look green. Delete it with its CI lines.
set -u

binary=build/tests/merovingian-conformance-tests
export MEROVINGIAN_TEST_DISABLE_HARDENING=1

# Runs a command for at most $1 seconds.
bounded() {
    limit=$1
    shift
    "$@" &
    bounded_pid=$!
    (
        sleep "$limit"
        kill -9 "$bounded_pid" 2>/dev/null
    ) &
    bounded_timer=$!
    wait "$bounded_pid"
    bounded_status=$?
    kill "$bounded_timer" 2>/dev/null
    return "$bounded_status"
}

group() {
    echo "::group::[netbsd-diag] $1"
}

# Everything that can be learned about hung process $1, which ends up dead.
dump_stacks() {
    group "threads of $1, as the kernel sees them"
    bounded 30 ps -s -l -p "$1" 2>&1
    bounded 30 ps -s -o lid,lstate,wchan,lname,time -p "$1" 2>&1
    echo "::endgroup::"

    group "open files of $1"
    bounded 30 fstat -p "$1" 2>&1
    echo "::endgroup::"

    group "system calls of $1 over 15 s"
    trace=$(mktemp)
    if bounded 10 ktrace -f "$trace" -p "$1" 2>&1; then
        sleep 15
        bounded 10 ktrace -C 2>&1
        bounded 30 kdump -f "$trace" 2>&1 | tail -n 120 | cut -c1-160
    fi
    echo "::endgroup::"

    group "thread states after the trace"
    bounded 30 ps -s -l -p "$1" 2>&1
    echo "::endgroup::"

    # Catch2 handles SIGABRT and SIGTERM; it leaves SIGQUIT to dump core.
    kill -QUIT "$1" 2>/dev/null
    waited_for_exit=0
    while kill -0 "$1" 2>/dev/null && [ "$waited_for_exit" -lt 30 ]; do
        sleep 1
        waited_for_exit=$((waited_for_exit + 1))
    done
    if kill -0 "$1" 2>/dev/null; then
        echo "[netbsd-diag] SIGQUIT did not end it after ${waited_for_exit}s"
        bounded 30 ps -s -l -p "$1" 2>&1
        kill -9 "$1" 2>/dev/null
        sleep 5
        echo "[netbsd-diag] alive after SIGKILL: $(kill -0 "$1" 2>/dev/null && echo yes || echo no)"
    fi

    for core in $(find . -maxdepth 4 -name 'merovingian-conf*.core' 2>/dev/null); do
        group "stacks from $core"
        bounded 300 gdb --batch -ex 'info threads' -ex 'thread apply all bt' "$binary" "$core" 2>&1 | cut -c1-200
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

# The scenario alone: it hung by its third run, in under a minute.
runs=0
started=$(date +%s)
while [ $(($(date +%s) - started)) -lt 600 ]; do
    runs=$((runs + 1))
    if ! run_watched 120 "[omit_members]"; then
        echo "[netbsd-diag] the scenario alone hung on run $runs"
        exit 1
    fi
done
echo "[netbsd-diag] the scenario alone did not hang in $runs runs"
exit 1
