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

# The libc alone, with none of this project's code: does res_query hang where res_nquery does not?
repro_dir=$(mktemp -d)
cat >"$repro_dir/repro.c" <<'REPRO'
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

#define THREADS 8
#define LOOKUPS 40

static void *lookup(void *arg)
{
    unsigned char answer[4096];
    char name[128];
    long index = (long)arg;
    for (int i = 0; i < LOOKUPS; i++)
    {
        snprintf(name, sizeof name, "_matrix-fed._tcp.t%ld-%d.invalid", index, i);
#ifdef PER_CALL
        struct __res_state state;
        memset(&state, 0, sizeof state);
        if (res_ninit(&state) == 0)
        {
            res_nquery(&state, name, C_IN, T_SRV, answer, sizeof answer);
            res_ndestroy(&state);
        }
#else
        res_query(name, C_IN, T_SRV, answer, sizeof answer);
#endif
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    for (long i = 0; i < THREADS; i++)
    {
        pthread_create(&threads[i], NULL, lookup, (void *)i);
    }
    for (long i = 0; i < THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
REPRO

compiler=$(command -v cc || command -v clang)
"$compiler" -pthread -o "$repro_dir/shared" "$repro_dir/repro.c" 2>&1 | tail -n 20
"$compiler" -pthread -DPER_CALL -o "$repro_dir/per_call" "$repro_dir/repro.c" 2>&1 | tail -n 20

# Runs program $1 up to five times, for at most 60 s each, and reports the first hang with the kernel's view.
repro_rounds() {
    round=0
    while [ "$round" -lt 5 ]; do
        round=$((round + 1))
        "$repro_dir/$1" >/dev/null 2>&1 &
        repro_pid=$!
        waited=0
        while kill -0 "$repro_pid" 2>/dev/null && [ "$waited" -lt 60 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        if kill -0 "$repro_pid" 2>/dev/null; then
            echo "[netbsd-diag] repro $1 still running after 60s on round $round"
            bounded 30 ps -s -o lid,lstate,wchan,lname,time -p "$repro_pid" 2>&1
            kill -9 "$repro_pid" 2>/dev/null
            return 0
        fi
        wait "$repro_pid"
        echo "[netbsd-diag] repro $1 round $round finished in ${waited}s with status $?"
    done
    echo "[netbsd-diag] repro $1 did not hang in $round rounds"
}

group "libc alone: res_query from eight threads, then res_nquery on a state per call"
repro_rounds shared
repro_rounds per_call
echo "::endgroup::"

# The fixed binaries. Before the fix the first of these hung on its third and fifth runs.
runs=0
started=$(date +%s)
while [ $(($(date +%s) - started)) -lt 480 ]; do
    runs=$((runs + 1))
    binary=build/tests/merovingian-conformance-tests
    if ! run_watched 120 "[omit_members]"; then
        echo "[netbsd-diag] [omit_members] hung on run $runs"
        exit 1
    fi
    binary=build/tests/merovingian-unit-tests
    if ! run_watched 120 "[system_resolver]"; then
        echo "[netbsd-diag] [system_resolver] hung on run $runs"
        exit 1
    fi
done
echo "[netbsd-diag] neither hung in $runs runs"
exit 1
