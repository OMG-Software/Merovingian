#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Entrypoint of the Complement image (tests/complement/AGENTS.md).
#
# It starts as root because Complement starts containers itself and does not
# pass --cap-drop=ALL, and only root can empty the capability bounding set the
# server's startup self-check requires. It prepares the container, then
# replaces itself with the server as the unprivileged merovingian user.
#
# Complement starts containers again from snapshots, so every step is safe to
# run on a container that has started before.
#
# Environment:
#   SERVER_NAME                                     set by Complement
#   MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK   "true" waives Landlock for
#                                                   the federation worker
#                                                   (default "false")

set -eu

lib=/usr/local/lib/merovingian-complement
owner=merovingian:merovingian
ca_dir=/complement/ca
config=/etc/merovingian/merovingian.conf
state=/var/lib/merovingian

if [ "$(id -u)" != 0 ]; then
    echo "complement: the entrypoint must start as root to drop the capability bounding set" >&2
    exit 1
fi

# 1. The config. render-config.sh refuses a SERVER_NAME that is not a server
#    name, and an unknown Landlock waiver, before anything is written. It is
#    put in place once step 2b has added the application services.
install -d -m 0755 /etc/merovingian /etc/merovingian/tls
"$lib/render-config.sh" "$lib/merovingian.conf.template" "${SERVER_NAME:-}" \
    "${MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK:-false}" >"$config.tmp"
chmod 0644 "$config.tmp"

# 2. The master key and database directory, kept across restarts.
"$lib/prepare-state.sh" "$state" "$SERVER_NAME" "$owner"

# 2b. The application service registrations Complement copied in. Their
#     as_token and hs_token are secrets, so they go beside the master key, out
#     of the directories the federation worker's Landlock grants.
registrations=$("$lib/install-appservices.sh" /complement/appservice "$state/secrets/appservice" merovingian)
if [ -n "$registrations" ]; then
    printf 'appservice.registration_files=%s\n' "$registrations" >>"$config.tmp"
fi
mv -f "$config.tmp" "$config"

# 3. The federation listener's certificate, from Complement's CA.
"$lib/mint-tls.sh" "$ca_dir" "$SERVER_NAME" /etc/merovingian/tls/server.crt "$state/secrets/tls.key" "$owner"

# 4. Trust Complement's CA for outbound federation. The server reads the
#    system trust store, which has no room for a CA of its own.
install -m 0644 "$ca_dir/ca.crt" /usr/local/share/ca-certificates/complement-ca.crt
update-ca-certificates >/dev/null

# 5. nginx puts the loopback client listener on 8008. It forks into the
#    background and outlives this shell, which is replaced next.
nginx -t -q
nginx

# 6. The server, as merovingian, with no capabilities and no way to gain any.
exec setpriv --reuid=merovingian --regid=merovingian --init-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /usr/bin/merovingian-server --config "$config"
