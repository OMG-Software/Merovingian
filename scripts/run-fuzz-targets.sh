#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the fuzz harnesses with libFuzzer and run each target for a bounded
# duration. The script exits non-zero on the first finding so CI fails fast.
# Targets are intentionally short by default - the goal here is a regression
# gate on every push, not exhaustive corpus generation.

set -eu

builddir=build-fuzz
duration_seconds=120
runs_limit=0
cc=${CC:-clang}
cxx=${CXX:-clang++}

usage() {
    cat <<'EOF'
Usage:
  sh scripts/run-fuzz-targets.sh [options]

Options:
  --builddir <path>     Meson build directory. Default: build-fuzz.
  --duration <seconds>  Per-target wall-clock budget. Default: 120.
  --runs <count>        libFuzzer -runs= cap (0 = unlimited). Default: 0.
  --cc <command>        C compiler. Default: clang or $CC.
  --cxx <command>       C++ compiler. Default: clang++ or $CXX.
  --help                Show this help text.
EOF
}

fail() {
    printf 'fuzz runner: %s\n' "$1" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --builddir)
            shift
            [ "$#" -gt 0 ] || fail "--builddir requires a path"
            builddir=$1
            ;;
        --duration)
            shift
            [ "$#" -gt 0 ] || fail "--duration requires a value"
            duration_seconds=$1
            ;;
        --runs)
            shift
            [ "$#" -gt 0 ] || fail "--runs requires a value"
            runs_limit=$1
            ;;
        --cc)
            shift
            [ "$#" -gt 0 ] || fail "--cc requires a command"
            cc=$1
            ;;
        --cxx)
            shift
            [ "$#" -gt 0 ] || fail "--cxx requires a command"
            cxx=$1
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
    shift
done

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
cd "$repo_root"

command -v "$cc" >/dev/null 2>&1 || fail "missing command: $cc"
command -v "$cxx" >/dev/null 2>&1 || fail "missing command: $cxx"
command -v meson >/dev/null 2>&1 || fail "missing command: meson"
command -v ninja >/dev/null 2>&1 || fail "missing command: ninja"

# libFuzzer is only available with clang. The fuzz harness meson.build also
# guards against this, but check early so the operator sees a clear message.
case "$cxx" in
    *clang*) ;;
    *) fail "fuzz harness requires clang; got $cxx" ;;
esac

if [ -f "$builddir/build.ninja" ]; then
    env CC="$cc" CXX="$cxx" meson setup "$builddir" --reconfigure -Dbuild_tests=false -Dbuild_fuzz=true
else
    env CC="$cc" CXX="$cxx" meson setup "$builddir" -Dbuild_tests=false -Dbuild_fuzz=true
fi

meson compile -C "$builddir"

corpus_root="$builddir/fuzz-corpus"
mkdir -p "$corpus_root"

run_target() {
    target_name=$1
    target_binary=$2

    [ -x "$target_binary" ] || fail "fuzz target missing: $target_binary"

    corpus_dir="$corpus_root/$target_name"
    mkdir -p "$corpus_dir"

    printf 'Running fuzz target %s for %ss\n' "$target_name" "$duration_seconds"

    # -max_total_time bounds wall-clock; -runs caps iterations when set;
    # -error_exitcode ensures any finding propagates a non-zero status; -timeout
    # bounds per-input wall time so a slow input cannot stall the run forever.
    # ASAN_OPTIONS=abort_on_error guarantees the harness exits on the first
    # sanitizer report rather than masking errors as warnings.
    fuzz_args="-max_total_time=$duration_seconds -error_exitcode=77 -timeout=25 -print_final_stats=1"
    if [ "$runs_limit" -gt 0 ]; then
        fuzz_args="$fuzz_args -runs=$runs_limit"
    fi

    # shellcheck disable=SC2086
    ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 \
        UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        "$target_binary" $fuzz_args "$corpus_dir"
}

run_target fuzz-canonicaljson "$builddir/tests/fuzz/fuzz-canonicaljson"
run_target fuzz-http-request "$builddir/tests/fuzz/fuzz-http-request"

printf 'All fuzz targets completed cleanly.\n'
