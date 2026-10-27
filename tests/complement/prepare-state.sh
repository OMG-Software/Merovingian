#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage: prepare-state.sh STATE_DIR SERVER_NAME OWNER
#
# Prepares the server's persistent state under STATE_DIR:
#
#   STATE_DIR/                 0755, owned by whoever runs this (root)
#   STATE_DIR/server-name      the server this state belongs to
#   STATE_DIR/secrets/         0711, owned by whoever runs this; holds the
#                              master key and TLS key, each 0400 and owned by
#                              OWNER (user:group)
#   STATE_DIR/data/            0700, owned by OWNER: the SQLite database
#
# The entrypoint writes into STATE_DIR and secrets/ as root on every start, so
# OWNER, the server's user, must not be able to create entries there: a link
# it planted would be followed by root on the next start. Only data/ is
# OWNER's, and root never writes into it.
#
# Complement snapshots containers and starts them again, so this runs on every
# start and must keep what an earlier start made: the master key protects the
# signing key in the database, and other servers have cached that signing key.
# State made for one server name is never served under another, and a master
# key this script did not record a server name for is never adopted.

set -eu

here=$(dirname "$0")
. "$here/server-name.sh"

fail() {
    echo "complement: $1" >&2
    exit 1
}

if [ "$#" -ne 3 ]; then
    echo "usage: prepare-state.sh STATE_DIR SERVER_NAME OWNER" >&2
    exit 2
fi
state=$1
server_name=$2
owner=$3

complement_require_server_name "$server_name"

umask 077
record="$state/server-name"
master_key="$state/secrets/master.key"
invoker="$(id -u):$(id -g)"

for directory in "$state" "$state/secrets" "$state/data"; do
    if [ -L "$directory" ]; then
        fail "${directory} is a symbolic link; refusing to write through it"
    fi
    mkdir -p "$directory"
done
chown "$invoker" "$state" "$state/secrets"
chmod 0755 "$state"
chmod 0711 "$state/secrets"
chown "$owner" "$state/data"
chmod 0700 "$state/data"
# Left by an interrupted start, or planted: removed, never written through.
rm -f "$record.tmp" "$master_key.tmp"

if [ -e "$record" ]; then
    recorded=$(cat "$record")
    if [ "$recorded" != "$server_name" ]; then
        fail "this state belongs to ${recorded}; refusing to serve it as ${server_name}"
    fi
elif [ -e "$master_key" ] || [ -n "$(ls -A "$state/data")" ]; then
    fail "${state} holds state with no recorded server name; refusing to adopt it"
else
    printf '%s\n' "$server_name" >"$record.tmp"
    mv -f "$record.tmp" "$record"
fi

if [ ! -e "$master_key" ]; then
    # A 256-bit key, owner read-only, as the server's secret-file check requires.
    dd if=/dev/urandom of="$master_key.tmp" bs=32 count=1 2>/dev/null
    chown "$owner" "$master_key.tmp"
    chmod 0400 "$master_key.tmp"
    mv -f "$master_key.tmp" "$master_key"
fi

if [ -L "$master_key" ] || [ ! -f "$master_key" ] || [ "$(wc -c <"$master_key" | tr -d ' ')" != 32 ]; then
    fail "${master_key} is not a 32-byte regular file; refusing to start on it"
fi
