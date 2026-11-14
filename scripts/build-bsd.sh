#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

builddir=build
cc=${CC:-clang}
cxx=${CXX:-clang++}
pkg_config=${PKG_CONFIG:-}
wrap_mode=forcefallback
profile=
build_tests=true
build_fuzz=false
run_tests=1
setup_only=0
compile_only=0
dry_run=0
buildtype=
sanitize=
coverage=false
skip_job=
hardening=
jobs=

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
tool_shim_dir=$repo_root/scripts/tool-shims
cd "$repo_root"

usage() {
    cat <<'EOF'
Usage:
  sh scripts/build-bsd.sh [options]

Options:
  --builddir <path>   Meson build directory. Default: build.
  --cc <command>      C compiler command. Default: clang or $CC.
  --cxx <command>     C++ compiler command. Default: clang++ or $CXX.
  --pkg-config <cmd>  pkg-config-compatible command. Default: pkgconf, then pkg-config.
  --wrap-mode <mode>  Meson wrap mode. Default: forcefallback.
  --profile <name>    Named profile: debug, release, sanitizer, coverage, fuzz, hardened.
  --buildtype <type>  Meson buildtype, for example debug.
  --sanitize <list>   Meson b_sanitize value, for example address,undefined.
  --coverage          Enable Meson coverage instrumentation.
  --build-fuzz        Enable fuzz harness targets.
  --hardening         Enable hardening flags (-Dhardening=true).
  --skip-job <name>   After the tests, fail on any Catch2 skip that job <name> in
                      tests/expected_skips.json does not list (ADR-0546).
  --jobs <n>          Run at most <n> compile jobs and <n> tests at once.
                      Default: Meson's own choice, one per CPU or more.
  --no-tests          Build without running tests.
  --setup-only        Configure/reconfigure Meson and stop.
  --compile-only      Configure/reconfigure and compile, but do not test.
  --dry-run           Print commands without running them.
  --help              Show this help text.

Examples:
  sh scripts/build-bsd.sh
  sh scripts/build-bsd.sh --profile hardened --builddir build-hardened
  sh scripts/build-bsd.sh --builddir build-freebsd --compile-only
EOF
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

quote_arg() {
    case "$1" in
        *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=,+-]*)
            printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

print_command() {
    printf '+'
    for arg in "$@"; do
        printf ' '
        quote_arg "$arg"
    done
    printf '\n'
}

run() {
    print_command "$@"
    if [ "$dry_run" -eq 0 ]; then
        "$@"
    fi
}

select_pkg_config() {
    if [ -n "$pkg_config" ]; then
        printf '%s\n' "$pkg_config"
        return
    fi
    if command -v pkgconf >/dev/null 2>&1; then
        printf '%s\n' pkgconf
        return
    fi
    printf '%s\n' pkg-config
}

check_command() {
    if [ "$dry_run" -eq 1 ]; then
        return
    fi
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

check_pkg_config_module() {
    if [ "$dry_run" -eq 1 ]; then
        return
    fi
    "$pkg_config" --exists "$1" || fail "missing pkg-config module: $1"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --builddir)
            shift
            [ "$#" -gt 0 ] || fail "--builddir requires a path"
            builddir=$1
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
        --pkg-config)
            shift
            [ "$#" -gt 0 ] || fail "--pkg-config requires a command"
            pkg_config=$1
            ;;
        --wrap-mode)
            shift
            [ "$#" -gt 0 ] || fail "--wrap-mode requires a value"
            wrap_mode=$1
            ;;
        --profile)
            shift
            [ "$#" -gt 0 ] || fail "--profile requires a value"
            profile=$1
            ;;
        --buildtype)
            shift
            [ "$#" -gt 0 ] || fail "--buildtype requires a value"
            buildtype=$1
            ;;
        --sanitize)
            shift
            [ "$#" -gt 0 ] || fail "--sanitize requires a value"
            sanitize=$1
            ;;
        --coverage)
            coverage=true
            ;;
        --build-fuzz)
            build_fuzz=true
            ;;
        --hardening)
            hardening=true
            ;;
        --skip-job)
            shift
            [ "$#" -gt 0 ] || fail "--skip-job requires a job name"
            skip_job=$1
            ;;
        --jobs)
            shift
            [ "$#" -gt 0 ] || fail "--jobs requires a number"
            case "$1" in
                ""|*[!0-9]*|0*) fail "--jobs requires a positive whole number, not '$1'" ;;
            esac
            jobs=$1
            ;;
        --no-tests)
            run_tests=0
            ;;
        --setup-only)
            setup_only=1
            run_tests=0
            ;;
        --compile-only)
            compile_only=1
            run_tests=0
            ;;
        --dry-run)
            dry_run=1
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

case "$profile" in
    "")
        ;;
    debug)
        [ -n "$buildtype" ] || buildtype=debug
        ;;
    release)
        [ -n "$buildtype" ] || buildtype=release
        ;;
    sanitizer)
        [ -n "$buildtype" ] || buildtype=debug
        [ -n "$sanitize" ] || sanitize=address,undefined
        ;;
    coverage)
        [ -n "$buildtype" ] || buildtype=debugoptimized
        coverage=true
        ;;
    fuzz)
        [ -n "$buildtype" ] || buildtype=debugoptimized
        build_fuzz=true
        ;;
    hardened)
        [ -n "$buildtype" ] || buildtype=release
        hardening=true
        ;;
    *)
        fail "unknown profile: $profile"
        ;;
esac

pkg_config=$(select_pkg_config)

check_command "$cc"
check_command "$cxx"
check_command meson
check_command ninja
check_command "$pkg_config"
# libsodium, openssl, libpq, and libcurl are always linked from the system (the
# meson dependencies use allow_fallback: false), regardless of wrap mode.
check_pkg_config_module libsodium
check_pkg_config_module openssl
check_pkg_config_module libpq
check_pkg_config_module libcurl

meson_options="-Dbuild_tests=$build_tests -Dbuild_fuzz=$build_fuzz --wrap-mode=$wrap_mode"
[ -z "$buildtype" ] || meson_options="$meson_options --buildtype=$buildtype"
[ -z "$sanitize" ] || meson_options="$meson_options -Db_sanitize=$sanitize"
[ "$coverage" = false ] || meson_options="$meson_options -Db_coverage=true"
[ -z "$hardening" ] || meson_options="$meson_options -Dhardening=$hardening"

if [ -f "$builddir/build.ninja" ]; then
    # shellcheck disable=SC2086
    run env PATH="$tool_shim_dir:$PATH" CC="$cc" CXX="$cxx" PKG_CONFIG="$pkg_config" meson setup "$builddir" --reconfigure $meson_options
else
    # shellcheck disable=SC2086
    run env PATH="$tool_shim_dir:$PATH" CC="$cc" CXX="$cxx" PKG_CONFIG="$pkg_config" meson setup "$builddir" $meson_options
fi

if [ "$setup_only" -eq 1 ]; then
    exit 0
fi

if [ -n "$jobs" ]; then
    run meson compile -C "$builddir" -j "$jobs"
else
    run meson compile -C "$builddir"
fi

if [ "$compile_only" -eq 1 ] || [ "$run_tests" -eq 0 ]; then
    exit 0
fi

# Runtime hardening (seccomp/pledge/unveil) is permanent in-process. The Catch2
# test runner executes many scenarios in one process, so disable it for the
# test suite while still applying it in production server binaries.
export MEROVINGIAN_TEST_DISABLE_HARDENING=1

# Meson does not read MESON_TEST_TIMEOUT_MULTIPLIER from the environment.
# Translate the env var used by the sanitizers workflow into the matching
# command-line flag so long-running integration tests get the extra time.
# It defaults to 2 here: the BSD CI VMs run under emulation and the same
# test binary's duration varies by 20-40% between runs, which pushed the
# unit, conformance and integration binaries past their meson limits
# (600 s / 900 s) on runs where nothing hung. An explicit value still wins.
# tests/meson.build sets the integration binary's value on the BSDs to half of
# its 30 minutes because of this default (ADR-0509): change them together.
timeout_multiplier="${MESON_TEST_TIMEOUT_MULTIPLIER:-2}"
meson_test_timeout_args="--timeout-multiplier ${timeout_multiplier}"
meson_test_jobs_args=""
if [ -n "$jobs" ]; then
    meson_test_jobs_args="--num-processes ${jobs}"
fi

# With --skip-job each Catch2 binary also writes an XML report, and
# scripts/check_expected_skips.py fails the build on a skipped test case the job
# does not expect: meson reports a skipped Catch2 test case as passed (ADR-0546).
skip_reports=
if [ -n "$skip_job" ]; then
    case "$builddir" in
        /*) skip_reports=$builddir/skip-reports ;;
        *) skip_reports=$repo_root/$builddir/skip-reports ;;
    esac
    run rm -rf "$skip_reports"
    run mkdir -p "$skip_reports"
fi

test_status=0
# shellcheck disable=SC2086
run env MEROVINGIAN_TEST_DISABLE_HARDENING=1 MEROVINGIAN_CATCH_REPORT_DIR="$skip_reports" meson test -C "$builddir" --print-errorlogs ${meson_test_timeout_args} ${meson_test_jobs_args} || test_status=$?

gate_status=0
if [ -n "$skip_job" ]; then
    # FreeBSD and NetBSD install Python only as meson's dependency, as a versioned binary (python3.11) with no
    # python3 or python link. Prefer python3, then the interpreter meson itself runs on, then any python3.N.
    skip_python=
    if command -v python3 >/dev/null 2>&1; then
        skip_python=python3
    else
        meson_path=$(command -v meson 2>/dev/null || true)
        if [ -n "$meson_path" ]; then
            # "#!/usr/local/bin/python3.11" names it; "#!/usr/bin/env python3.11" names it second.
            meson_interpreter=$(sed -n '1{
                s/^#![[:space:]]*//
                s/^[^[:space:]]*\/env[[:space:]][[:space:]]*//
                s/[[:space:]].*$//
                p
            }' "$meson_path")
            case "$meson_interpreter" in
                /*) ;;
                *) meson_interpreter=$(command -v "$meson_interpreter" 2>/dev/null || true) ;;
            esac
            if [ -n "$meson_interpreter" ] && [ -x "$meson_interpreter" ]; then
                skip_python=$meson_interpreter
            fi
        fi
        if [ -z "$skip_python" ]; then
            for minor in 14 13 12 11 10 9; do
                if command -v "python3.$minor" >/dev/null 2>&1; then
                    skip_python=python3.$minor
                    break
                fi
            done
        fi
    fi
    if [ -z "$skip_python" ]; then
        echo "build-bsd.sh: no Python interpreter found for check_expected_skips.py" >&2
        gate_status=2
    else
        run "$skip_python" "$script_dir/check_expected_skips.py" --job "$skip_job" --reports "$skip_reports" || gate_status=$?
    fi
fi

if [ "$test_status" -ne 0 ]; then
    exit "$test_status"
fi
exit "$gate_status"
