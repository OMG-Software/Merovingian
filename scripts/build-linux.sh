#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

builddir=build-clang22
cc=${CC:-clang-22}
cxx=${CXX:-clang++-22}
wrap_mode=default
build_tests=true
build_fuzz=false
run_tests=1
setup_only=0
compile_only=0
dry_run=0

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
cd "$repo_root"

usage() {
    cat <<'EOF'
Usage:
  sh scripts/build-linux.sh [options]

Options:
  --builddir <path>   Meson build directory. Default: build-clang22.
  --cc <command>      C compiler command. Default: clang-22 or $CC.
  --cxx <command>     C++ compiler command. Default: clang++-22 or $CXX.
  --wrap-mode <mode>  Meson wrap mode. Default: default.
  --build-fuzz        Enable fuzz harness targets.
  --no-tests          Build without running tests.
  --setup-only        Configure/reconfigure Meson and stop.
  --compile-only      Configure/reconfigure and compile, but do not test.
  --dry-run           Print commands without running them.
  --help              Show this help text.

Examples:
  sh scripts/build-linux.sh
  sh scripts/build-linux.sh --builddir build-clang22 --cc clang-22 --cxx clang++-22
EOF
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

quote_arg() {
    case "$1" in
        *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+-]*)
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
    pkg-config --exists "$1" || fail "missing pkg-config module: $1"
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
        --wrap-mode)
            shift
            [ "$#" -gt 0 ] || fail "--wrap-mode requires a value"
            wrap_mode=$1
            ;;
        --build-fuzz)
            build_fuzz=true
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

check_command "$cc"
check_command "$cxx"
check_command meson
check_command ninja
check_command pkg-config
check_pkg_config_module libsodium
check_pkg_config_module openssl
check_pkg_config_module sqlite3

if [ -f "$builddir/build.ninja" ]; then
    run env CC="$cc" CXX="$cxx" meson setup "$builddir" --reconfigure \
        -Dbuild_tests="$build_tests" -Dbuild_fuzz="$build_fuzz" --wrap-mode="$wrap_mode"
else
    run env CC="$cc" CXX="$cxx" meson setup "$builddir" \
        -Dbuild_tests="$build_tests" -Dbuild_fuzz="$build_fuzz" --wrap-mode="$wrap_mode"
fi

if [ "$setup_only" -eq 1 ]; then
    exit 0
fi

run meson compile -C "$builddir"

if [ "$compile_only" -eq 1 ] || [ "$run_tests" -eq 0 ]; then
    exit 0
fi

run meson test -C "$builddir" --print-errorlogs
