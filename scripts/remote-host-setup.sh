#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# One-time setup of a remote build host, a VM or another machine, for
# `python build.py vm` (ADR-0752). On a Debian-family Linux host it installs the
# build packages with apt-get and a current Meson/Ninja in a virtual environment
# linked into ~/.local/bin, which build.py vm puts first on PATH. On FreeBSD it
# installs the packages the FreeBSD CI job installs, Meson and Ninja included,
# with pkg. Run it on the remote host, in the checkout build.py vm synced, as
# root or as a user who can use sudo or doas. It is not for WSL, which has
# scripts/wsl-setup.sh.

set -eu

tools_venv=${MEROVINGIAN_TOOLS_VENV:-"$HOME/.local/share/merovingian-tools"}
bin_dir=${MEROVINGIAN_TOOLS_BIN:-"$HOME/.local/bin"}
os_release=/etc/os-release
dry_run=0

usage() {
    cat <<'EOF'
Usage:
  sh scripts/remote-host-setup.sh [options]

Options:
  --tools-venv <path>  Python virtual environment for Meson/Ninja.
                       Default: ~/.local/share/merovingian-tools.
  --bin-dir <path>     Directory for Meson/Ninja symlinks. Default: ~/.local/bin.
  --os-release <file>  Distribution description to check. Default: /etc/os-release.
  --dry-run            Print commands without running them.
  --help               Show this help text.

Supports Ubuntu, Debian, distributions whose ID_LIKE names either (for
example Linux Mint), and FreeBSD. On FreeBSD --tools-venv and --bin-dir are
unused: pkg's Meson is current. After setup, run python build.py vm locally.
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

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tools-venv)
            shift
            [ "$#" -gt 0 ] || fail "--tools-venv requires a path"
            tools_venv=$1
            ;;
        --bin-dir)
            shift
            [ "$#" -gt 0 ] || fail "--bin-dir requires a path"
            bin_dir=$1
            ;;
        --os-release)
            shift
            [ "$#" -gt 0 ] || fail "--os-release requires a file"
            os_release=$1
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

[ -r "$os_release" ] || fail "cannot read $os_release to detect the distribution"
# Read only the two fields needed, without sourcing the file.
os_id=$(sed -n 's/^ID=//p' "$os_release" | tr -d "\"'")
os_id_like=$(sed -n 's/^ID_LIKE=//p' "$os_release" | tr -d "\"'")
case " $os_id $os_id_like " in
    *" ubuntu "*|*" debian "*)
        family=debian
        ;;
    " freebsd "*)
        family=freebsd
        ;;
    *)
        fail "scripts/remote-host-setup.sh supports Ubuntu, Debian, their derivatives and FreeBSD only (ID=$os_id)"
        ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    as_root=
elif command -v sudo >/dev/null 2>&1; then
    as_root=sudo
elif command -v doas >/dev/null 2>&1; then
    as_root=doas
elif [ "$dry_run" -eq 1 ]; then
    as_root=sudo
else
    fail "run scripts/remote-host-setup.sh as root, or install sudo or doas"
fi

if [ "$family" = freebsd ]; then
    # The FreeBSD CI job's packages (.github/workflows/ci.yml), plus python3 for
    # build.py vm's lock and the skip gate. pkg's Meson is new enough.
    packages="meson ninja llvm catch2 pkgconf git perl5 bison flex gmake openssl libsodium postgresql17-client python3 curl png libjpeg-turbo"
    # shellcheck disable=SC2086
    run $as_root pkg install -y $packages
    cat <<EOF

The remote build host is ready. Run python build.py vm on the local machine.
EOF
    exit 0
fi

# Everything build-linux.sh checks for, including libcurl, plus the optional
# libpng and libjpeg-turbo for the thumbnail worker, and python3-venv for Meson.
packages="build-essential clang lld python3 python3-venv pkg-config git perl bison flex m4 libssl-dev libsodium-dev libpq-dev libcurl4-openssl-dev libpng-dev libturbojpeg0-dev catch2"

# shellcheck disable=SC2086
run $as_root apt-get update
# shellcheck disable=SC2086
run $as_root apt-get install -y $packages

# Ubuntu 24.04's Meson is too old for the C++26 build.
run python3 -m venv "$tools_venv"
run "$tools_venv/bin/python" -m pip install --upgrade pip
run "$tools_venv/bin/python" -m pip install --upgrade "meson>=1.11" ninja
run mkdir -p "$bin_dir"
run ln -sf "$tools_venv/bin/meson" "$bin_dir/meson"
run ln -sf "$tools_venv/bin/ninja" "$bin_dir/ninja"

cat <<EOF

The remote build host is ready. Run python build.py vm on the local machine.
EOF
