#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Startup hardening gate for a packaged merovingian-server (audit OPS-5).
#
# Boots the given server binary against a throwaway SQLite config bound to
# loopback, waits for its final startup hardening self-check, and passes only
# when every check reports `enabled`, the check count matches what the server
# says it ran, and the server then stops cleanly on SIGTERM. It is the CI
# counterpart to the refusal in src/main.cpp: a package built at -O0 (no
# _FORTIFY_SOURCE) or missing a hardening control fails here instead of on an
# operator's host.
#
# Run it as the unprivileged user the package runs as, with an empty capability
# bounding set (for example `setpriv --bounding-set=-all`, or
# `docker run --cap-drop=ALL`): the server refuses to run as root and cannot
# drop the bounding set without CAP_SETPCAP.
#
# Without --federation-worker the server finds its federation worker at its
# built-in libexec path, so a pass also proves the package installed it there.
set -eu

timeout=60
client_port=18008
federation_port=18009
federation_worker=""

usage() {
    cat >&2 <<'EOF'
usage: check-startup-hardening-gate.sh [options] <merovingian-server>

options:
  --timeout <seconds>          Seconds to wait for startup and for shutdown (default 60).
  --client-port <port>         Loopback port for the client listener (default 18008).
  --federation-port <port>     Loopback port for the federation listener (default 18009).
  --federation-worker <path>   Federation worker binary (default: the server's libexec path).
EOF
    exit 2
}

fail() {
    echo "startup hardening gate: FAIL: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --timeout)
            shift
            [ "$#" -gt 0 ] || usage
            timeout=$1
            ;;
        --client-port)
            shift
            [ "$#" -gt 0 ] || usage
            client_port=$1
            ;;
        --federation-port)
            shift
            [ "$#" -gt 0 ] || usage
            federation_port=$1
            ;;
        --federation-worker)
            shift
            [ "$#" -gt 0 ] || usage
            federation_worker=$1
            ;;
        -h | --help)
            usage
            ;;
        -*)
            usage
            ;;
        *)
            break
            ;;
    esac
    shift
done

[ "$#" -eq 1 ] || usage
server=$1
[ -x "$server" ] || fail "server binary is not executable: $server"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/merovingian-gate.XXXXXX")
chmod 0700 "$workdir"
config="$workdir/merovingian.conf"
master_key="$workdir/master.key"
log="$workdir/server.log"
pid_file="$workdir/server.pid"
status_file="$workdir/server.status"
wrapper_pid=""

cleanup() {
    if [ -s "$pid_file" ] && [ ! -e "$status_file" ]; then
        kill -KILL "$(cat "$pid_file")" 2>/dev/null || true
    fi
    if [ -n "$wrapper_pid" ]; then
        wait "$wrapper_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# A 256-bit master key the server can read but nobody else can, as its secret
# file checks require.
(umask 077 && dd if=/dev/urandom of="$master_key" bs=32 count=1 2>/dev/null)
chmod 0400 "$master_key"

{
    echo "server.name=localhost.test"
    echo "server.public_baseurl=https://localhost.test"
    echo "listeners.client.bind=127.0.0.1:${client_port}"
    echo "listeners.client.tls=false"
    echo "listeners.federation.bind=127.0.0.1:${federation_port}"
    echo "listeners.federation.tls=false"
    echo "database.backend=sqlite"
    echo "database.sqlite_path=${workdir}/merovingian.sqlite3"
    echo "security.secrets.master_key_file=${master_key}"
    # The gate is about the main process's self-check. Landlock is still
    # applied to the worker wherever the kernel (or container seccomp profile)
    # offers it; this only stops its absence failing the boot (ADR-0062).
    echo "federation.worker.allow_without_landlock=true"
    if [ -n "$federation_worker" ]; then
        echo "federation.worker.binary=${federation_worker}"
    fi
} >"$config"
# The server rejects a config that group or other can write.
chmod 0644 "$config"

# Run the server from a wrapper that records its exit status, so a server that
# dies is noticed at once rather than mistaken for a live, unreaped child.
(
    "$server" --config "$config" >"$log" 2>&1 &
    echo "$!" >"$pid_file"
    status=0
    wait "$!" || status=$?
    echo "$status" >"$status_file"
) &
wrapper_pid=$!

show_checks() {
    echo "--- hardening self-check reported by $server ---"
    grep -o 'Hardening self-check: [^"]*' "$log" || echo "(no hardening self-check lines)"
    grep -o 'Hardening readiness: [^"]*' "$log" || true
}

fail_with_log() {
    show_checks
    echo "--- last 50 lines of server log ---"
    tail -n 50 "$log" || true
    fail "$*"
}

# The readiness line is printed once, by the final self-check that decides
# whether the server may serve.
elapsed=0
while ! grep -q 'Hardening readiness: ' "$log" 2>/dev/null; do
    if [ -e "$status_file" ]; then
        fail_with_log "server exited with status $(cat "$status_file") before its final hardening self-check"
    fi
    if [ "$elapsed" -ge "$timeout" ]; then
        fail_with_log "no final hardening self-check within ${timeout}s"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

checks=$(grep -o 'Hardening self-check: [^"]*' "$log" | sed 's/^Hardening self-check: //')
expected=$(sed -n 's/.*Startup hardening checks: \([0-9][0-9]*\).*/\1/p' "$log" | tail -n 1)
enabled=$(printf '%s\n' "$checks" | grep -c '^[^=]*=enabled\( \|$\)' || true)
not_enabled=$(printf '%s\n' "$checks" | grep -v '^[^=]*=enabled\( \|$\)' | grep -c . || true)

[ -n "$expected" ] || fail_with_log "server did not report how many hardening checks it ran"
[ "$not_enabled" -eq 0 ] || fail_with_log "$not_enabled hardening check(s) not enabled"
[ "$enabled" -eq "$expected" ] || fail_with_log "server ran $expected hardening checks but reported $enabled as enabled"
grep -q 'Hardening readiness: ready=true blockers=0' "$log" || fail_with_log "server did not report itself ready"

# A refusal after the self-check (or a crash) means it never served.
sleep 1
[ ! -e "$status_file" ] || fail_with_log "server exited with status $(cat "$status_file") after its hardening self-check"

show_checks

kill -TERM "$(cat "$pid_file")"
elapsed=0
while [ ! -e "$status_file" ]; do
    if [ "$elapsed" -ge "$timeout" ]; then
        fail_with_log "server did not stop within ${timeout}s of SIGTERM"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
status=$(cat "$status_file")
[ "$status" -eq 0 ] || fail_with_log "server exited with status $status on SIGTERM"

echo "startup hardening gate: PASS: all $expected hardening checks enabled"
