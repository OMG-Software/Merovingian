#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Refresh the apt package index on an Ubuntu CI runner or Ubuntu container, and
# fall back to public DNS resolvers when the runner's own resolver cannot reach
# the archive (ADR-0650).
#
# `apt-get update --error-on=any` fails when any index could not be fetched;
# plain `apt-get update` exits 0 when it reached nothing, and the install that
# follows then fails with no sign of why. On 2026-11-11 the resolver GitHub's
# runners use (and the one Docker hands their containers) answered nothing for
# *.ubuntu.com for hours while Cloudflare's still did. After a failed refresh
# this script points /etc/resolv.conf at Cloudflare and Google for the rest of
# the job and retries. DNS is not trusted for integrity: apt verifies the
# archive's signed Release files whichever resolver found the mirror.
#
# A host runner's /etc/resolv.conf is a symlink to systemd-resolved's stub,
# which forwards to the failing resolver, so the link is replaced by a file. A
# container's is a bind mount that cannot be removed, so it is rewritten in
# place.
#
# Runs as root in a container and through sudo on a host runner. Idempotent:
# a second run refreshes the index again, through whichever resolver is set.
# MEROVINGIAN_RESOLV_CONF and MEROVINGIAN_APT_RETRY_DELAY exist for
# tests/tooling/test_ci_workflow.py and are not set in any workflow.
set -eu

RESOLV_CONF="${MEROVINGIAN_RESOLV_CONF:-/etc/resolv.conf}"
RETRY_DELAY="${MEROVINGIAN_APT_RETRY_DELAY:-15}"
case "${RETRY_DELAY}" in
    '' | *[!0-9]*)
        echo "MEROVINGIAN_APT_RETRY_DELAY must be a whole number of seconds: ${RETRY_DELAY}" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    as_root() { "$@"; }
else
    as_root() { sudo "$@"; }
fi

if as_root apt-get update --error-on=any; then
    exit 0
fi

echo "::warning::apt-get update failed; retrying through public DNS resolvers (ADR-0650)"
if [ -L "${RESOLV_CONF}" ]; then
    as_root rm -f "${RESOLV_CONF}"
fi
printf 'nameserver 1.1.1.1\nnameserver 1.0.0.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n' \
    | as_root tee "${RESOLV_CONF}" >/dev/null

attempt=1
while ! as_root apt-get update --error-on=any; do
    if [ "${attempt}" -ge 3 ]; then
        echo "apt-get update failed through the public DNS resolvers too" >&2
        exit 1
    fi
    sleep $((RETRY_DELAY * attempt))
    attempt=$((attempt + 1))
done
