#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# CI only: installs packages in the vmactions OpenBSD VMs, retrying, and falling back from the
# CDN to the origin mirror (ADR-0650).
#
# OpenBSD's pkg_add exits 0 even when it installed nothing: on 2026-11-11 the CDN's TLS
# handshake failed, every package came back "Can't find", and the job only failed later, at
# "meson: not found". So success is judged by the commands and pkg-config modules the build
# needs being present afterwards, never by pkg_add's status.
#
# Usage: ci-openbsd-pkg-add.sh --require "command ..." [--require-pkg-config "module ..."] package ...
#
# Idempotent: packages already installed are left as they are. MEROVINGIAN_PKG_RETRY_DELAY
# exists for tests/tooling/test_ci_workflow.py and is not set in any workflow.
set -u

usage() {
    echo "usage: ci-openbsd-pkg-add.sh --require \"command ...\" [--require-pkg-config \"module ...\"] package ..." >&2
    exit 2
}

if [ "$#" -lt 3 ] || [ "$1" != "--require" ]; then
    usage
fi
REQUIRED=$2
shift 2
REQUIRED_MODULES=""
if [ "$1" = "--require-pkg-config" ]; then
    [ "$#" -ge 3 ] || usage
    REQUIRED_MODULES=$2
    shift 2
fi

RETRY_DELAY="${MEROVINGIAN_PKG_RETRY_DELAY:-10}"
case "${RETRY_DELAY}" in
    '' | *[!0-9]*)
        echo "MEROVINGIAN_PKG_RETRY_DELAY must be a whole number of seconds: ${RETRY_DELAY}" >&2
        exit 2
        ;;
esac

# Prints the required commands and pkg-config modules still missing, space-separated; prints
# nothing when all exist.
missing_requirements() {
    for command_name in ${REQUIRED}; do
        command -v "${command_name}" >/dev/null 2>&1 || printf '%s ' "${command_name}"
    done
    for module in ${REQUIRED_MODULES}; do
        pkg-config --exists "${module}" 2>/dev/null || printf 'pkg-config:%s ' "${module}"
    done
}

package_path="pub/OpenBSD/$(uname -r)/packages/$(uname -m)/"
for mirror in cdn.openbsd.org ftp.openbsd.org; do
    PKG_PATH="https://${mirror}/${package_path}"
    export PKG_PATH
    attempt=1
    while [ "${attempt}" -le 3 ]; do
        pkg_add -I "$@"
        missing=$(missing_requirements)
        if [ -z "${missing}" ]; then
            exit 0
        fi
        echo "::warning::pkg_add through ${mirror} (attempt ${attempt}) left missing: ${missing}"
        sleep $((RETRY_DELAY * attempt))
        attempt=$((attempt + 1))
    done
done

echo "pkg_add failed through every mirror; still missing: $(missing_requirements)" >&2
exit 1
