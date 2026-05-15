#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

builddir=build
cc=${CC:-clang}
cxx=${CXX:-clang++}
pkg_config=${PKG_CONFIG:-}
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
  sh scripts/build-bsd.sh [options]

Options:
  --builddir <path>   Meson build directory. Default: build.
  --cc <command>      C compiler command. Default: clang or $CC.
  --cxx <command>     C++ compiler command. Default: clang++ or $CXX.
  --pkg-config <cmd>  pkg-config-compatible command. Default: pkgconf, then pkg-config.
  --wrap-mode <mode>  Meson wrap mode. Default: default.
  --build-fuzz        Enable fuzz harness targets.
  --no-tests          Build without running tests.
  --setup-only        Configure/reconfigure Meson and stop.
  --compile-only      Configure/reconfigure and compile, but do not test.
  --dry-run           Print commands without running them.
  --help              Show this help text.

Examples:
  sh scripts/build-bsd.sh
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

pkg_config=$(select_pkg_config)

check_command "$cc"
check_command "$cxx"
check_command meson
check_command ninja
check_command "$pkg_config"
check_pkg_config_module libsodium
check_pkg_config_module openssl
check_pkg_config_module libpq
check_pkg_config_module sqlite3

meson_options="-Dbuild_tests=$build_tests -Dbuild_fuzz=$build_fuzz --wrap-mode=$wrap_mode"

if [ -f "$builddir/build.ninja" ]; then
    # shellcheck disable=SC2086
    run env CC="$cc" CXX="$cxx" PKG_CONFIG="$pkg_config" meson setup "$builddir" --reconfigure $meson_options
else
    # shellcheck disable=SC2086
    run env CC="$cc" CXX="$cxx" PKG_CONFIG="$pkg_config" meson setup "$builddir" $meson_options
fi

if [ "$setup_only" -eq 1 ]; then
    exit 0
fi

run meson compile -C "$builddir"

if [ "$compile_only" -eq 1 ] || [ "$run_tests" -eq 0 ]; then
    exit 0
fi

run meson test -C "$builddir" --print-errorlogs
