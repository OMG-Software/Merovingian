#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# CI only: installs packages in the vmactions OpenBSD VMs, retrying, and falling back from the
# CDN to the origin mirror (ADR-0650).
#
# OpenBSD's pkg_add exits 0 even when it installed nothing: on 2026-11-11 the CDN's TLS
# handshake failed, every package came back "Can't find", and the job only failed later, at
# "meson: not found". So success is judged by the commands the build needs being on PATH
# afterwards, never by pkg_add's status.
#
# Usage: ci-openbsd-pkg-add.sh --require "command ..." package ...
#
# Idempotent: packages already installed are left as they are. MEROVINGIAN_PKG_RETRY_DELAY
# exists for tests/tooling/test_ci_workflow.py and is not set in any workflow.
set -u

if [ "$#" -lt 3 ] || [ "$1" != "--require" ]; then
    echo "usage: ci-openbsd-pkg-add.sh --require \"command ...\" package ..." >&2
    exit 2
fi
REQUIRED=$2
shift 2

RETRY_DELAY="${MEROVINGIAN_PKG_RETRY_DELAY:-10}"
case "${RETRY_DELAY}" in
    '' | *[!0-9]*)
        echo "MEROVINGIAN_PKG_RETRY_DELAY must be a whole number of seconds: ${RETRY_DELAY}" >&2
        exit 2
        ;;
esac

# Prints the required commands still missing, space-separated; prints nothing when all exist.
missing_commands() {
    for command_name in ${REQUIRED}; do
        command -v "${command_name}" >/dev/null 2>&1 || printf '%s ' "${command_name}"
    done
}

package_path="pub/OpenBSD/$(uname -r)/packages/$(uname -m)/"
for mirror in cdn.openbsd.org ftp.openbsd.org; do
    PKG_PATH="https://${mirror}/${package_path}"
    export PKG_PATH
    attempt=1
    while [ "${attempt}" -le 3 ]; do
        pkg_add -I "$@"
        missing=$(missing_commands)
        if [ -z "${missing}" ]; then
            exit 0
        fi
        echo "::warning::pkg_add through ${mirror} (attempt ${attempt}) left missing: ${missing}"
        sleep $((RETRY_DELAY * attempt))
        attempt=$((attempt + 1))
    done
done

echo "pkg_add failed through every mirror; still missing: $(missing_commands)" >&2
exit 1
