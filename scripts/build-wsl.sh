#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build Merovingian under WSL (Windows Subsystem for Linux).
#
# WSL mounts the Windows filesystem (NTFS) at /mnt/c/ etc.  Automake's depcomp
# bootstrap fails on NTFS, so curl must be configured with
# --disable-dependency-tracking.  This script detects a stale curl subproject
# (for example, an extracted source tree whose packagefile copy predates that
# flag) and wipes it so Meson re-runs configure with the correct options from
# subprojects/packagefiles/curl/meson.build.
#
# Run scripts/wsl-setup.sh first if you have not already done so.

set -eu

builddir=build-wsl
cc=${CC:-clang}
cxx=${CXX:-clang++}
pkg_config=${PKG_CONFIG:-pkg-config}
wrap_mode=forcefallback
profile=
build_tests=true
build_fuzz=false
run_tests=1
setup_only=0
compile_only=0
dry_run=0
clean=0
buildtype=
sanitize=
coverage=false
hardening=

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
tool_shim_dir=$repo_root/scripts/tool-shims
packagefile_curl_meson="$repo_root/subprojects/packagefiles/curl/meson.build"
runtime_tool_shim_dir=${MEROVINGIAN_WSL_TOOL_SHIM_DIR:-"$HOME/.cache/merovingian-wsl-tool-shims"}
repo_make_shim="$tool_shim_dir/make"
runtime_make_shim="$runtime_tool_shim_dir/make"
cd "$repo_root"

usage() {
    cat <<'EOF'
Usage:
  sh scripts/build-wsl.sh [options]

Options:
  --builddir <path>   Meson build directory. Default: build-wsl.
  --cc <command>      C compiler command. Default: clang or $CC.
  --cxx <command>     C++ compiler command. Default: clang++ or $CXX.
  --pkg-config <cmd>  pkg-config-compatible command. Default: pkg-config.
  --wrap-mode <mode>  Meson wrap mode. Default: forcefallback.
  --profile <name>    Named profile: debug, release, sanitizer, coverage, fuzz, hardened.
  --buildtype <type>  Meson buildtype, for example debug.
  --sanitize <list>   Meson b_sanitize value, for example address,undefined.
  --coverage          Enable Meson coverage instrumentation.
  --build-fuzz        Enable fuzz harness targets.
  --hardening         Enable hardening flags.
  --clean             Wipe the entire build directory before configuring.
  --no-tests          Build without running tests.
  --setup-only        Configure/reconfigure Meson and stop.
  --compile-only      Configure/reconfigure and compile, but do not test.
  --dry-run           Print commands without running them.
  --help              Show this help text.

Examples:
  sh scripts/build-wsl.sh
  sh scripts/build-wsl.sh --profile hardened --builddir build-wsl-hardened
  sh scripts/build-wsl.sh --builddir build-tsan --buildtype debug --sanitize thread

Run scripts/wsl-setup.sh once to install build tools and system packages.
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

stage_runtime_make_shim() {
    if [ "$dry_run" -eq 1 ]; then
        print_command sh -c "LC_ALL=C tr -d '\015' < \"\$1\" > \"\$2\"" sh "$repo_make_shim" "$runtime_make_shim"
        return
    fi

    if [ ! -f "$runtime_make_shim" ] || ! cmp -s "$repo_make_shim" "$runtime_make_shim"; then
        run sh -c "LC_ALL=C tr -d '\015' < \"\$1\" > \"\$2\"" sh "$repo_make_shim" "$runtime_make_shim"
    fi
}

prepare_runtime_tool_shims() {
    if [ "$dry_run" -eq 1 ]; then
        print_command mkdir -p "$runtime_tool_shim_dir"
        print_command sh -c "LC_ALL=C tr -d '\015' < \"\$1\" > \"\$2\"" sh "$repo_make_shim" "$runtime_make_shim"
        print_command chmod 0755 "$runtime_make_shim"
        return
    fi

    [ -f "$repo_make_shim" ] || fail "missing tool shim: $repo_make_shim"
    run mkdir -p "$runtime_tool_shim_dir"
    stage_runtime_make_shim
    run chmod 0755 "$runtime_make_shim"
}

check_command() {
    if [ "$dry_run" -eq 1 ]; then
        return
    fi
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1 (run scripts/wsl-setup.sh)"
}

check_pkg_config_module() {
    if [ "$dry_run" -eq 1 ]; then
        return
    fi
    "$pkg_config" --exists "$1" || fail "missing pkg-config module: $1 (run scripts/wsl-setup.sh)"
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
        --clean)
            clean=1
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

check_command "$cc"
check_command "$cxx"
check_command meson
check_command ninja
check_command "$pkg_config"
check_pkg_config_module libsodium
check_pkg_config_module openssl
check_pkg_config_module libpq
prepare_runtime_tool_shims

# --clean: wipe the build directory entirely and start fresh.
if [ "$clean" -eq 1 ] && [ -e "$builddir" ]; then
    printf 'build-wsl: --clean requested, wiping %s\n' "$builddir"
    run rm -rf "$builddir"
fi

# Detect a stale curl subproject: if a previous configure ran without
# --disable-dependency-tracking it will fail on NTFS-backed filesystems.
# Meson extracts the curl source tree under repo_root/subprojects/curl-<version>
# and drives configure in builddir/subprojects/curl-<version>/build/config.log.
# Wipe only the stale curl source/build directories so Meson re-extracts and
# re-configures them with the current packagefile; all other subprojects are
# left intact. This still runs after --clean so a wiped build directory does not
# reuse a stale extracted source tree.
if [ "$dry_run" -eq 0 ] && [ -d "$repo_root/subprojects" ]; then
    for source_curl_dir in "$repo_root"/subprojects/curl-"*/"; do
        [ -d "$source_curl_dir" ] || continue
        curl_name=$(basename "$source_curl_dir")
        build_curl_dir="$builddir/subprojects/$curl_name/"
        source_meson="${source_curl_dir}meson.build"
        build_config_log="${build_curl_dir}build/config.log"

        if [ ! -f "$source_meson" ]; then
            printf 'build-wsl: incomplete curl source tree, wiping %s\n' "$source_curl_dir"
            run rm -rf "$source_curl_dir"
            if [ -d "$build_curl_dir" ]; then
                printf 'build-wsl: wiping matching curl build tree %s\n' "$build_curl_dir"
                run rm -rf "$build_curl_dir"
            fi
            continue
        fi

        if ! cmp -s "$packagefile_curl_meson" "$source_meson"; then
            printf 'build-wsl: stale extracted curl packagefile detected in %s\n' "$source_curl_dir"
            printf 'build-wsl: wiping %s so Meson re-extracts the current packagefile\n' "$source_curl_dir"
            run rm -rf "$source_curl_dir"
            if [ -d "$build_curl_dir" ]; then
                printf 'build-wsl: wiping matching curl build tree %s\n' "$build_curl_dir"
                run rm -rf "$build_curl_dir"
            fi
            continue
        fi

        if [ -f "$build_config_log" ]; then
            if ! grep -q -- '--disable-dependency-tracking' "$build_config_log"; then
                printf 'build-wsl: stale curl configure log detected (no --disable-dependency-tracking)\n'
                printf 'build-wsl: wiping %s to force a clean configure\n' "$build_curl_dir"
                run rm -rf "$build_curl_dir"
            fi
        elif [ -d "$build_curl_dir" ]; then
            # No config.log under build/ means configure never finished; wipe and retry.
            printf 'build-wsl: incomplete curl build tree, wiping %s\n' "$build_curl_dir"
            run rm -rf "$build_curl_dir"
        fi
    done
fi

meson_options="-Dbuild_tests=$build_tests -Dbuild_fuzz=$build_fuzz --wrap-mode=$wrap_mode"
[ -z "$buildtype" ] || meson_options="$meson_options --buildtype=$buildtype"
[ -z "$sanitize" ] || meson_options="$meson_options -Db_sanitize=$sanitize"
[ "$coverage" = false ] || meson_options="$meson_options -Db_coverage=true"
[ -z "$hardening" ] || meson_options="$meson_options -Dhardening=$hardening"

if [ -f "$builddir/build.ninja" ]; then
    # shellcheck disable=SC2086
    run env PATH="$runtime_tool_shim_dir:$tool_shim_dir:$PATH" CC="$cc" CXX="$cxx" meson setup "$builddir" --reconfigure $meson_options
else
    # shellcheck disable=SC2086
    run env PATH="$runtime_tool_shim_dir:$tool_shim_dir:$PATH" CC="$cc" CXX="$cxx" meson setup "$builddir" $meson_options
fi

if [ "$setup_only" -eq 1 ]; then
    exit 0
fi

run meson compile -C "$builddir"

if [ "$compile_only" -eq 1 ] || [ "$run_tests" -eq 0 ]; then
    exit 0
fi

run meson test -C "$builddir" --print-errorlogs
