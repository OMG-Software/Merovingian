#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

tools_venv=${MEROVINGIAN_TOOLS_VENV:-"$HOME/.local/share/merovingian-tools"}
bin_dir=${MEROVINGIAN_TOOLS_BIN:-"$HOME/.local/bin"}
dry_run=0

usage() {
    cat <<'EOF'
Usage:
  sh scripts/wsl-setup.sh [options]

Options:
  --tools-venv <path>  Python virtual environment for Meson/Ninja.
                       Default: ~/.local/share/merovingian-tools.
  --bin-dir <path>     Directory for Meson/Ninja symlinks. Default: ~/.local/bin.
  --dry-run            Print commands without running them.
  --help               Show this help text.

After setup:
  export PATH="$HOME/.local/bin:$PATH"
  sh scripts/build-linux.sh --builddir build-wsl
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

if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    fail "cannot detect host distribution"
fi

case "${ID:-}" in
    ubuntu|debian)
        ;;
    *)
        fail "scripts/wsl-setup.sh currently supports Ubuntu/Debian WSL only"
        ;;
esac

packages="build-essential clang lld python3 python3-venv pkg-config git libsodium-dev libpq-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev catch2 clang-format clang-tidy cppcheck"

run sudo apt-get update
# shellcheck disable=SC2086
run sudo apt-get install -y $packages

run python3 -m venv "$tools_venv"
run "$tools_venv/bin/python" -m pip install --upgrade pip
run "$tools_venv/bin/python" -m pip install --upgrade "meson>=1.11" ninja
run mkdir -p "$bin_dir"
run ln -sf "$tools_venv/bin/meson" "$bin_dir/meson"
run ln -sf "$tools_venv/bin/ninja" "$bin_dir/ninja"

cat <<EOF

WSL build tools are ready.

Add this to the current shell before building:

  export PATH="$bin_dir:\$PATH"

Then build with:

  sh scripts/build-linux.sh --builddir build-wsl

EOF
