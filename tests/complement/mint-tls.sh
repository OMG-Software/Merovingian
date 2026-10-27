#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage: mint-tls.sh CA_DIR SERVER_NAME CERT_PATH KEY_PATH OWNER
#
# Mints the federation listener's certificate from Complement's CA
# (CA_DIR/ca.crt and CA_DIR/ca.key, mounted at /complement/ca), so the other
# servers in a run trust it. A fresh P-256 key and a one-day certificate are
# made at every start, so nothing older than the CA mounted now is served.
#
#   CERT_PATH  0644, root-owned: the server's config-file check refuses group
#              or other write
#   KEY_PATH   0400, owned by OWNER: the server's secret-file check
#
# Nothing is written to CA_DIR, which may be mounted read-only: the serial
# number is random rather than kept in a CA serial file.

set -eu

here=$(dirname "$0")
. "$here/server-name.sh"

fail() {
    echo "complement: $1" >&2
    exit 1
}

if [ "$#" -ne 5 ]; then
    echo "usage: mint-tls.sh CA_DIR SERVER_NAME CERT_PATH KEY_PATH OWNER" >&2
    exit 2
fi
ca_dir=$1
server_name=$2
cert=$3
key=$4
owner=$5

complement_require_server_name "$server_name"
[ -r "$ca_dir/ca.crt" ] && [ -r "$ca_dir/ca.key" ] || fail "no readable ca.crt and ca.key in ${ca_dir}"

host=$(complement_server_name_host "$server_name")
case $server_name in
    \[*) san="IP:${host}" ;;
    *)
        if printf '%s\n' "$host" | grep -Eqx '[0-9]{1,3}(\.[0-9]{1,3}){3}'; then
            san="IP:${host}"
        else
            san="DNS:${host}"
        fi
        ;;
esac

umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# `openssl req` refuses to run without a config file, and not every system
# ships one. Everything this script needs is on the command line, so it uses
# a minimal config of its own rather than whatever the host has. No
# `prompt = no`: with it, LibreSSL takes the subject from the config's
# section instead of -subj. The section's entry is a prompt label -subj
# replaces, and stdin is closed below so nothing can prompt.
cat >"$work/openssl.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
commonName = Common Name
EOF
OPENSSL_CONF="$work/openssl.cnf"
export OPENSSL_CONF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/key.pem" 2>/dev/null
openssl req -new -key "$work/key.pem" -subj "/CN=${host}" -out "$work/request.csr" </dev/null
cat >"$work/extensions.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${san}
EOF
openssl x509 -req -in "$work/request.csr" \
    -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -days 1 -sha256 \
    -extfile "$work/extensions.cnf" \
    -out "$work/cert.pem" 2>/dev/null

# Each file goes in under a temporary name beside its target and is renamed
# over it, so a failed step never leaves a half-written file. The server is not
# running yet: the entrypoint starts it only after this script succeeds.
# A leftover temporary file, or a link in its place, is removed rather than
# written through.
rm -f "$key.tmp" "$cert.tmp"
cp "$work/key.pem" "$key.tmp"
chown "$owner" "$key.tmp"
chmod 0400 "$key.tmp"
mv -f "$key.tmp" "$key"

cp "$work/cert.pem" "$cert.tmp"
chmod 0644 "$cert.tmp"
mv -f "$cert.tmp" "$cert"
