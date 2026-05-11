#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

dry_run=0
install_packages=1
configure_build=1
check_only=0
builddir=build
package_manager=${MEROVINGIAN_SETUP_PACKAGE_MANAGER:-}
detected_os=${MEROVINGIAN_SETUP_OS:-}

# Keep Meson setup anchored at the repository root regardless of the caller's
# current directory.
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)
cd "$repo_root"

usage() {
    cat <<'EOF'
Usage:
  sh scripts/setup-dev-env.sh [options]

Options:
  --dry-run                 Print commands without running them.
  --check-only              Check for required tools and pkg-config modules only.
  --no-install              Do not install operating-system packages.
  --no-configure            Do not create or validate the Meson build directory.
  --builddir <path>         Meson build directory to configure. Default: build.
  --package-manager <name>  Override package manager detection.
  --help                    Show this help text.

Supported package managers:
  Linux: apt, dnf, zypper, pacman, apk
  BSD:   pkg, pkg_add, pkgin
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

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        run "$@"
        return
    fi

    if command -v sudo >/dev/null 2>&1; then
        run sudo "$@"
        return
    fi

    if command -v doas >/dev/null 2>&1; then
        run doas "$@"
        return
    fi

    if [ "$dry_run" -eq 1 ]; then
        run sudo "$@"
        return
    fi

    fail "root privileges are required; install sudo/doas or run the script as root"
}

detect_os() {
    if [ -n "$detected_os" ]; then
        printf '%s\n' "$detected_os"
        return
    fi

    uname -s
}

detect_package_manager() {
    if [ -n "$package_manager" ]; then
        printf '%s\n' "$package_manager"
        return
    fi

    os_name=$(detect_os)
    case "$os_name" in
        Linux)
            for candidate in apt-get dnf zypper pacman apk; do
                if command -v "$candidate" >/dev/null 2>&1; then
                    case "$candidate" in
                        apt-get) printf '%s\n' apt ;;
                        *) printf '%s\n' "$candidate" ;;
                    esac
                    return
                fi
            done
            ;;
        FreeBSD | HardenedBSD | DragonFly)
            if command -v pkg >/dev/null 2>&1; then
                printf '%s\n' pkg
                return
            fi
            ;;
        OpenBSD)
            if command -v pkg_add >/dev/null 2>&1; then
                printf '%s\n' pkg_add
                return
            fi
            ;;
        NetBSD)
            if command -v pkgin >/dev/null 2>&1; then
                printf '%s\n' pkgin
                return
            fi
            if command -v pkg_add >/dev/null 2>&1; then
                printf '%s\n' pkg_add
                return
            fi
            ;;
    esac

    fail "unsupported operating system or package manager: $os_name"
}

package_list_for() {
    case "$1" in
        apt)
            printf '%s\n' "build-essential clang lld meson ninja-build pkg-config git python3 libsodium-dev libpq-dev libsqlite3-dev libssl-dev catch2 clang-format clang-tidy cppcheck"
            ;;
        dnf)
            printf '%s\n' "gcc-c++ clang lld meson ninja-build pkgconf-pkg-config git python3 libsodium-devel libpq-devel sqlite-devel openssl-devel catch-devel clang-tools-extra cppcheck"
            ;;
        zypper)
            printf '%s\n' "gcc-c++ clang lld meson ninja pkg-config git python3 libsodium-devel postgresql-devel sqlite3-devel libopenssl-devel catch2-devel clang-tools cppcheck"
            ;;
        pacman)
            printf '%s\n' "base-devel clang lld meson ninja pkgconf git python libsodium postgresql-libs sqlite openssl catch2 clang-tools-extra cppcheck"
            ;;
        apk)
            printf '%s\n' "build-base clang lld meson ninja pkgconf git python3 libsodium-dev postgresql-dev sqlite-dev openssl-dev catch2-dev clang-extra-tools cppcheck"
            ;;
        pkg)
            printf '%s\n' "llvm meson ninja pkgconf git python3 libsodium postgresql16-client sqlite3 openssl catch2 cppcheck"
            ;;
        pkg_add)
            printf '%s\n' "llvm meson ninja pkgconf git libsodium postgresql-client sqlite3 openssl catch2 cppcheck"
            ;;
        pkgin)
            printf '%s\n' "clang meson ninja-build pkg-config git python311 libsodium postgresql16-client sqlite3 openssl catch2 cppcheck"
            ;;
        *)
            fail "unsupported package manager: $1"
            ;;
    esac
}

install_for() {
    manager=$1
    packages=$(package_list_for "$manager")

    case "$manager" in
        apt)
            run_as_root apt-get update
            # shellcheck disable=SC2086
            run_as_root apt-get install -y $packages
            ;;
        dnf)
            # shellcheck disable=SC2086
            run_as_root dnf install -y $packages
            ;;
        zypper)
            # shellcheck disable=SC2086
            run_as_root zypper install -y $packages
            ;;
        pacman)
            # shellcheck disable=SC2086
            run_as_root pacman -S --needed --noconfirm $packages
            ;;
        apk)
            # shellcheck disable=SC2086
            run_as_root apk add $packages
            ;;
        pkg)
            # shellcheck disable=SC2086
            run_as_root pkg install -y $packages
            ;;
        pkg_add)
            # shellcheck disable=SC2086
            run_as_root pkg_add $packages
            ;;
        pkgin)
            # shellcheck disable=SC2086
            run_as_root pkgin -y install $packages
            ;;
        *)
            fail "unsupported package manager: $manager"
            ;;
    esac
}

pkg_config_tool() {
    if command -v pkg-config >/dev/null 2>&1; then
        printf '%s\n' pkg-config
        return
    fi

    if command -v pkgconf >/dev/null 2>&1; then
        printf '%s\n' pkgconf
        return
    fi

    printf '%s\n' pkg-config
}

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing command: %s\n' "$1" >&2
        return 1
    fi

    printf 'found command: %s\n' "$1"
    return 0
}

check_pkg_config_module() {
    tool=$1
    module=$2

    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'missing command: %s\n' "$tool" >&2
        return 1
    fi

    if ! "$tool" --exists "$module"; then
        printf 'missing pkg-config module: %s\n' "$module" >&2
        return 1
    fi

    printf 'found pkg-config module: %s\n' "$module"
    return 0
}

check_environment() {
    status=0
    pc_tool=$(pkg_config_tool)

    for command_name in c++ git meson ninja; do
        check_command "$command_name" || status=1
    done

    for module in libsodium sqlite3 libpq openssl; do
        check_pkg_config_module "$pc_tool" "$module" || status=1
    done

    if [ "$status" -ne 0 ]; then
        fail "development environment check failed"
    fi
}

configure_meson_build() {
    if [ -d "$builddir" ]; then
        run meson setup "$builddir" --reconfigure
        return
    fi

    run meson setup "$builddir"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            dry_run=1
            ;;
        --check-only)
            check_only=1
            install_packages=0
            configure_build=0
            ;;
        --no-install)
            install_packages=0
            ;;
        --no-configure)
            configure_build=0
            ;;
        --builddir)
            shift
            [ "$#" -gt 0 ] || fail "--builddir requires a path"
            builddir=$1
            ;;
        --package-manager)
            shift
            [ "$#" -gt 0 ] || fail "--package-manager requires a value"
            package_manager=$1
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

if [ "$check_only" -eq 1 ]; then
    check_environment
    exit 0
fi

if [ "$install_packages" -eq 1 ]; then
    manager=$(detect_package_manager)
    install_for "$manager"
fi

if [ "$dry_run" -eq 0 ]; then
    check_environment
fi

if [ "$configure_build" -eq 1 ]; then
    configure_meson_build
fi
