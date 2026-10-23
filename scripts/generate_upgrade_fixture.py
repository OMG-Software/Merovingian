#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate cross-release database upgrade fixtures from an OLD Merovingian release.

Builds the given (old) commit in a WSL/Linux-native checkout, then runs the real
``merovingian-server`` of that release twice - once on SQLite, once on a
throwaway PostgreSQL cluster - drives an identical scenario through the real
HTTP Client-Server API, shuts the server down cleanly and writes:

    <output-dir>/merovingian.sqlite3   SQLite database after clean shutdown
    <output-dir>/postgresql.sql        pg_dump (plain SQL, column inserts, no COPY)
    <output-dir>/manifest.json         everything a test needs to prove the data survived

Nothing is hand-written into the databases: every row was written by the old server.

Usage (run inside Linux or WSL; needs git, meson, ninja, clang++, python3 and the
PostgreSQL server binaries, e.g. /usr/lib/postgresql/16/bin):

    python3 scripts/generate_upgrade_fixture.py <old-commit> <output-dir> \
        [--checkout-dir DIR] [--pg-bin-dir DIR]

The script is idempotent: outputs are overwritten, and the throwaway PostgreSQL
cluster, role and database are removed on exit. The old checkout is left in place
and reused (and rebuilt incrementally) on the next run.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

SERVER_NAME = "example.org"
REGISTRATION_TOKEN = "test-registration-token"
PG_ROLE = "merovingian_fixture"
PG_DATABASE = "merovingian_fixture"

ALICE = {"localpart": "alice", "password": "CorrectHorse7!", "device_id": "UPGRADE1"}
BOB = {"localpart": "bob", "password": "BatteryStaple9!", "device_id": "UPGRADE2"}

MEDIA_BODY = b"merovingian upgrade fixture media\n" * 10
MEDIA_CONTENT_TYPE = "text/plain"
ACCOUNT_DATA_TYPE = "org.merovingian.upgrade"
ACCOUNT_DATA_CONTENT = {"fixture": "0.11.13"}
PUSHER = {
    "kind": "http",
    "app_id": "org.merovingian.upgrade",
    "app_display_name": "Upgrade Fixture App",
    "device_display_name": "Upgrade Fixture Device",
    "lang": "en",
    "pushkey": "upgrade-pushkey",
    "data": {"url": "https://push.example.org/_matrix/push/v1/notify"},
}


class FixtureError(RuntimeError):
    """A step of the fixture generation failed."""


def log(message: str) -> None:
    print(f"[fixture] {message}", flush=True)


def run(
    args: list[str], *, cwd: pathlib.Path | None = None, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise FixtureError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
        )
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ---------------------------------------------------------------------------
# Building the old release
# ---------------------------------------------------------------------------


@dataclass
class OldRelease:
    commit: str
    version: str
    checkout: pathlib.Path
    server: pathlib.Path
    fed_worker: pathlib.Path
    schema_version: int


def prepare_old_release(source_repo: pathlib.Path, commit: str, checkout: pathlib.Path) -> OldRelease:
    if not (checkout / ".git").exists():
        log(f"cloning {source_repo} -> {checkout}")
        checkout.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "-q", str(source_repo), str(checkout)])
    full_commit = run(["git", "rev-parse", "--verify", f"{commit}^{{commit}}"], cwd=checkout, check=False)
    if full_commit.returncode != 0:
        run(["git", "fetch", "-q", str(source_repo), commit], cwd=checkout)
        full_commit = run(["git", "rev-parse", "--verify", f"{commit}^{{commit}}"], cwd=checkout)
    resolved = full_commit.stdout.strip()
    head = run(["git", "rev-parse", "HEAD"], cwd=checkout).stdout.strip()
    if head != resolved:
        log(f"checking out {resolved}")
        run(["git", "checkout", "-q", resolved], cwd=checkout)

    env = dict(os.environ)
    env["PATH"] = f"{pathlib.Path.home() / '.local' / 'bin'}{os.pathsep}{env['PATH']}"
    env.setdefault("CC", "clang")
    env.setdefault("CXX", "clang++")
    build = checkout / "build"
    if not (build / "build.ninja").exists():
        log("configuring old release (meson setup)")
        run(
            ["meson", "setup", "build", "-Dbuild_tests=false", "-Dbuild_fuzz=false", "--buildtype=release"],
            cwd=checkout,
            env=env,
        )
    log("building old release (ninja) - this can take several minutes on a cold tree")
    run(["ninja", "-C", "build"], cwd=checkout, env=env)

    meson_build = (checkout / "meson.build").read_text(encoding="utf-8")
    match = re.search(r"version:\s*'([^']+)'", meson_build)
    if not match:
        raise FixtureError("cannot read version from old meson.build")
    migration_numbers = [
        int(m.group(1))
        for m in (re.match(r"(\d+)_", path.name) for path in (checkout / "migrations").glob("*.sql"))
        if m
    ]
    server = build / "src" / "merovingian-server"
    fed_worker = build / "src" / "federation_worker" / "merovingian-fed-worker"
    for binary in (server, fed_worker):
        if not binary.exists():
            raise FixtureError(f"missing build product {binary}")
    return OldRelease(resolved, match.group(1), checkout, server, fed_worker, max(migration_numbers))


# ---------------------------------------------------------------------------
# Throwaway PostgreSQL cluster
# ---------------------------------------------------------------------------


def find_pg_bin_dir(explicit: str | None) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit)
    candidates = sorted(pathlib.Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)
    for candidate in candidates:
        if (candidate / "initdb").exists():
            return candidate
    found = shutil.which("initdb")
    if found:
        return pathlib.Path(found).parent
    raise FixtureError("PostgreSQL server binaries (initdb, pg_ctl) not found; pass --pg-bin-dir")


@dataclass
class PgCluster:
    bin_dir: pathlib.Path
    data_dir: pathlib.Path
    port: int
    socket_dir: pathlib.Path

    def tool(self, name: str) -> str:
        return str(self.bin_dir / name)

    def uri(self, database: str = PG_DATABASE) -> str:
        return f"postgresql://{PG_ROLE}@127.0.0.1:{self.port}/{database}?sslmode=disable"

    def psql(self, database: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run(
            [self.tool("psql"), "-h", "127.0.0.1", "-p", str(self.port), "-U", PG_ROLE, "-d", database, "-X", "-A",
             "-t", *args],
            check=check,
        )


@contextlib.contextmanager
def throwaway_postgres(bin_dir: pathlib.Path, scratch: pathlib.Path) -> Iterator[PgCluster]:
    """initdb a private cluster, create the fixture role + database, drop and remove everything on exit."""
    data_dir = scratch / "pgdata"
    socket_dir = scratch / "pgsock"
    socket_dir.mkdir()
    port = free_port()
    cluster = PgCluster(bin_dir, data_dir, port, socket_dir)
    run([cluster.tool("initdb"), "-D", str(data_dir), "-A", "trust", "-U", "postgres", "--no-sync", "-E", "UTF8",
         "--locale=C.UTF-8"])
    started = False
    try:
        run([cluster.tool("pg_ctl"), "-D", str(data_dir), "-w", "-l", str(scratch / "postgres.log"), "-o",
             f"-p {port} -k {socket_dir} -c listen_addresses=127.0.0.1 -c fsync=off", "start"])
        started = True
        admin = [cluster.tool("psql"), "-h", "127.0.0.1", "-p", str(port), "-U", "postgres", "-X", "-v",
                 "ON_ERROR_STOP=1", "-d", "postgres", "-c"]
        run([*admin, f"CREATE ROLE {PG_ROLE} LOGIN"])
        run([*admin, f"CREATE DATABASE {PG_DATABASE} OWNER {PG_ROLE} ENCODING 'UTF8' TEMPLATE template0"])
        yield cluster
        run([*admin, f"DROP DATABASE IF EXISTS {PG_DATABASE}_restore"], check=False)
        run([*admin, f"DROP DATABASE IF EXISTS {PG_DATABASE}"], check=False)
        run([*admin, f"DROP ROLE IF EXISTS {PG_ROLE}"], check=False)
    finally:
        if started:
            run([cluster.tool("pg_ctl"), "-D", str(data_dir), "-m", "fast", "-w", "stop"], check=False)


# ---------------------------------------------------------------------------
# Running the old server
# ---------------------------------------------------------------------------


@dataclass
class ServerHandle:
    process: subprocess.Popen[bytes]
    client_port: int
    log_path: pathlib.Path


def write_secret(path: pathlib.Path, data: bytes) -> None:
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def write_config(
    work: pathlib.Path,
    release: OldRelease,
    master_key: pathlib.Path,
    client_port: int,
    fed_port: int,
    database_lines: list[str],
) -> pathlib.Path:
    token_file = work / "registration-token"
    write_secret(token_file, REGISTRATION_TOKEN.encode())
    lines = [
        f"server.name={SERVER_NAME}",
        f"server.public_baseurl=https://{SERVER_NAME}",
        f"listeners.client.bind=127.0.0.1:{client_port}",
        "listeners.client.tls=false",
        "listeners.client.reverse_proxy=true",
        f"listeners.federation.bind=127.0.0.1:{fed_port}",
        "listeners.federation.tls=false",
        "listeners.federation.reverse_proxy=true",
        *database_lines,
        "security.registration.enabled=true",
        "security.registration.require_token=true",
        f"security.registration.token_file={token_file}",
        # Never expire: the upgrade test replays the recorded plaintext token against the new server.
        "security.access_token_lifetime_ms=0",
        "security.refresh_token_lifetime_ms=0",
        f"security.secrets.master_key_file={master_key}",
        f"federation.worker.binary={release.fed_worker}",
        "federation.worker.shards=1",
        "log_modules.*=info",
    ]
    config = work / "merovingian.conf"
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    config.chmod(0o600)
    return config


def capability_drop_prefix() -> list[str]:
    """Command prefix that gives the server an empty capability bounding set without root.

    The old server refuses to start unless its startup hardening self-check passes, and that
    needs the bounding set emptied; it cannot do that itself without CAP_SETPCAP. A user
    namespace mapping the current user to itself grants that capability to setpriv, which then
    drops everything before the server is exec'd. The server runs as the same unprivileged
    user, so file ownership and permissions are unchanged.
    """
    if os.geteuid() == 0:
        raise FixtureError("refusing to run the server as root; run this script as an unprivileged user")
    unshare, setpriv = shutil.which("unshare"), shutil.which("setpriv")
    if unshare is None or setpriv is None:
        return []
    return [unshare, "-U", f"--map-user={os.getuid()}", f"--map-group={os.getgid()}", "--keep-caps", setpriv,
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all"]


def start_server(release: OldRelease, config: pathlib.Path, work: pathlib.Path, client_port: int) -> ServerHandle:
    log_path = work / "server.log"
    log_handle = open(log_path, "wb")  # noqa: SIM115 - owned by the Popen for the server's lifetime
    process = subprocess.Popen(
        [*capability_drop_prefix(), str(release.server), "--config", str(config)],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=work,
    )
    log_handle.close()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise FixtureError(
                f"server exited early with {process.returncode}:\n{log_path.read_text(errors='replace')[-4000:]}"
            )
        try:
            conn = http.client.HTTPConnection("127.0.0.1", client_port, timeout=2)
            conn.request("GET", "/_matrix/client/versions")
            if conn.getresponse().status == 200:
                return ServerHandle(process, client_port, log_path)
        except OSError:
            pass
        time.sleep(0.3)
    process.kill()
    raise FixtureError(f"server did not become ready:\n{log_path.read_text(errors='replace')[-4000:]}")


def stop_server(handle: ServerHandle) -> int:
    handle.process.send_signal(signal.SIGTERM)
    try:
        return handle.process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        handle.process.kill()
        handle.process.wait()
        raise FixtureError("server did not exit within 60s of SIGTERM") from None


# ---------------------------------------------------------------------------
# HTTP client + scenario
# ---------------------------------------------------------------------------


@dataclass
class Api:
    port: int
    calls: list[dict[str, Any]] = field(default_factory=list)

    def request(
        self,
        step: str,
        method: str,
        path: str,
        body: Any = None,
        *,
        token: str | None = None,
        raw: bytes | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, Any]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload: bytes | None = raw
        if raw is None and body is not None:
            payload = json.dumps(body).encode()
        if payload is not None:
            headers["Content-Type"] = content_type
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        parsed: Any
        try:
            parsed = json.loads(data) if data else None
        except ValueError:
            parsed = data
        self.calls.append({"step": step, "method": method, "path": path.split("?")[0], "status": response.status})
        return response.status, parsed

    def ok(self, step: str, *args: Any, **kwargs: Any) -> Any:
        """Request that is expected to succeed; the status is logged either way."""
        status, parsed = self.request(step, *args, **kwargs)
        if not 200 <= status < 300:
            log(f"NON-2xx {status} for step '{step}': {parsed!r}")
            raise FixtureError(f"step '{step}' returned {status}: {parsed!r}")
        return parsed


def q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unpadded_b64(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def make_device_keys(user_id: str, device_id: str) -> dict[str, Any] | None:
    """Real, correctly signed device keys + one signed one-time key; None if `cryptography` is not installed."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    except ImportError:
        return None
    raw = serialization.Encoding.Raw
    pub = serialization.PublicFormat.Raw
    signing = ed25519.Ed25519PrivateKey.generate()
    identity = x25519.X25519PrivateKey.generate()
    one_time = x25519.X25519PrivateKey.generate()
    ed_pub = unpadded_b64(signing.public_key().public_bytes(raw, pub))
    device_keys: dict[str, Any] = {
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {
            f"curve25519:{device_id}": unpadded_b64(identity.public_key().public_bytes(raw, pub)),
            f"ed25519:{device_id}": ed_pub,
        },
    }
    device_keys["signatures"] = {
        user_id: {f"ed25519:{device_id}": unpadded_b64(signing.sign(canonical_json(device_keys)))}
    }
    otk: dict[str, Any] = {"key": unpadded_b64(one_time.public_key().public_bytes(raw, pub))}
    otk["signatures"] = {user_id: {f"ed25519:{device_id}": unpadded_b64(signing.sign(canonical_json(otk)))}}
    return {
        "device_keys": device_keys,
        "one_time_keys": {"signed_curve25519:AAAAAQ": otk},
        "ed25519_public_key": ed_pub,
    }


def run_scenario(api: Api) -> dict[str, Any]:
    result: dict[str, Any] = {}
    users: dict[str, dict[str, Any]] = {}
    for spec in (ALICE, BOB):
        lp = spec["localpart"]
        step = f"register {lp}"
        body = {
            "username": lp,
            "password": spec["password"],
            "inhibit_login": True,
            "auth": {"type": "m.login.registration_token", "token": REGISTRATION_TOKEN},
        }
        status, parsed = api.request(step, "POST", "/_matrix/client/v3/register", body)
        if status == 401 and isinstance(parsed, dict) and "session" in parsed:
            # Two-step UIA: retry with the session the server issued.
            body["auth"]["session"] = parsed["session"]
            status, parsed = api.request(step + " (with session)", "POST", "/_matrix/client/v3/register", body)
        if status != 200:
            raise FixtureError(f"{step} returned {status}: {parsed!r}")
        login = api.ok(
            f"login {lp}",
            "POST",
            "/_matrix/client/v3/login",
            {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": f"@{lp}:{SERVER_NAME}"},
                "password": spec["password"],
                "device_id": spec["device_id"],
                "initial_device_display_name": f"Upgrade fixture {spec['device_id']}",
            },
        )
        users[lp] = {
            "user_id": login["user_id"],
            "password": spec["password"],
            "device_id": login["device_id"],
            "access_token": login["access_token"],
        }
    alice, bob = users["alice"], users["bob"]
    a_tok, b_tok = alice["access_token"], bob["access_token"]

    displayname = "Alice Upgrade"
    api.ok("alice displayname", "PUT", f"/_matrix/client/v3/profile/{q(alice['user_id'])}/displayname",
           {"displayname": displayname}, token=a_tok)

    private_room = api.ok("alice create private room", "POST", "/_matrix/client/v3/createRoom",
                          {"name": "Upgrade Room", "preset": "private_chat", "visibility": "private"}, token=a_tok)[
        "room_id"]
    api.ok("alice invite bob", "POST", f"/_matrix/client/v3/rooms/{q(private_room)}/invite",
           {"user_id": bob["user_id"]}, token=a_tok)
    api.ok("bob join", "POST", f"/_matrix/client/v3/join/{q(private_room)}", {}, token=b_tok)

    messages = []
    plan = [(a_tok, "upgrade message 1"), (a_tok, "upgrade message 2"), (a_tok, "upgrade message 3"),
            (b_tok, "reply from bob")]
    for index, (token, text) in enumerate(plan, start=1):
        sender = alice["user_id"] if token == a_tok else bob["user_id"]
        sent = api.ok(f"send message {index}", "PUT",
                      f"/_matrix/client/v3/rooms/{q(private_room)}/send/m.room.message/upgrade-txn-{index}",
                      {"msgtype": "m.text", "body": text}, token=token)
        messages.append({"sender": sender, "event_id": sent["event_id"], "body": text})

    alias = f"#upgrade-public:{SERVER_NAME}"
    public_room = api.ok("alice create public room", "POST", "/_matrix/client/v3/createRoom",
                         {"name": "Upgrade Public", "room_alias_name": "upgrade-public", "preset": "public_chat",
                          "visibility": "public"}, token=a_tok)["room_id"]
    directory = api.ok("publicRooms listing", "GET", "/_matrix/client/v3/publicRooms")
    if not any(chunk.get("room_id") == public_room for chunk in directory.get("chunk", [])):
        log("room not in directory after createRoom visibility=public; publishing explicitly")
        api.ok("publish public room", "PUT", f"/_matrix/client/v3/directory/list/room/{q(public_room)}",
               {"visibility": "public"}, token=a_tok)
        directory = api.ok("publicRooms listing (2)", "GET", "/_matrix/client/v3/publicRooms")
        if not any(chunk.get("room_id") == public_room for chunk in directory.get("chunk", [])):
            raise FixtureError("public room is not in the published room directory")
    resolved = api.ok("resolve alias", "GET", f"/_matrix/client/v3/directory/room/{q(alias)}")
    if resolved.get("room_id") != public_room:
        raise FixtureError(f"alias resolved to {resolved!r}")

    uploaded = api.ok("alice upload media", "POST", "/_matrix/media/v3/upload?filename=upgrade-fixture.txt",
                      token=a_tok, raw=MEDIA_BODY, content_type=MEDIA_CONTENT_TYPE)
    mxc = uploaded["content_uri"]
    mxc_server, _, mxc_media_id = mxc.removeprefix("mxc://").partition("/")
    status, downloaded = api.request("alice download media", "GET",
                                     f"/_matrix/client/v1/media/download/{q(mxc_server)}/{q(mxc_media_id)}",
                                     token=a_tok)
    if status == 404:  # pre-authenticated-media release
        status, downloaded = api.request("alice download media (v3)", "GET",
                                         f"/_matrix/media/v3/download/{q(mxc_server)}/{q(mxc_media_id)}")
    if status != 200 or downloaded != MEDIA_BODY:
        raise FixtureError(f"media download mismatch (status {status})")

    api.ok("alice account data", "PUT",
           f"/_matrix/client/v3/user/{q(alice['user_id'])}/account_data/{ACCOUNT_DATA_TYPE}",
           ACCOUNT_DATA_CONTENT, token=a_tok)
    api.ok("alice set pusher", "POST", "/_matrix/client/v3/pushers/set", PUSHER, token=a_tok)

    # The upgrade test reads these keys back, so a fixture without them is incomplete: fail, never skip.
    keys = make_device_keys(alice["user_id"], alice["device_id"])
    if keys is None:
        raise FixtureError("keys/upload: the python 'cryptography' package is required to sign device keys")
    status, parsed = api.request("alice keys/upload", "POST", "/_matrix/client/v3/keys/upload",
                                 {"device_keys": keys["device_keys"], "one_time_keys": keys["one_time_keys"]},
                                 token=a_tok)
    if not 200 <= status < 300:
        raise FixtureError(f"keys/upload rejected with {status}: {parsed!r}")
    result["device_keys"] = {"device_keys": keys["device_keys"],
                             "one_time_keys": keys["one_time_keys"],
                             "ed25519_public_key": keys["ed25519_public_key"]}

    # Read-back checks, so a fixture is only produced from a server that really holds the data.
    got = api.ok("alice read messages", "GET",
                 f"/_matrix/client/v3/rooms/{q(private_room)}/messages?dir=b&limit=50", token=a_tok)
    bodies = [e["content"].get("body") for e in got["chunk"] if e.get("type") == "m.room.message"]
    if sorted(bodies) != sorted(m["body"] for m in messages):
        raise FixtureError(f"/messages bodies mismatch: {bodies!r}")
    sync = api.ok("alice initial sync", "GET", "/_matrix/client/v3/sync?timeout=0", token=a_tok)
    result["next_batch"] = sync.get("next_batch")

    result.update(
        users=users,
        displayname=displayname,
        private_room_id=private_room,
        public_room_id=public_room,
        alias=alias,
        messages=messages,
        media={
            "mxc_uri": mxc,
            "sha256": hashlib.sha256(MEDIA_BODY).hexdigest(),
            "content_type": MEDIA_CONTENT_TYPE,
            "size": len(MEDIA_BODY),
        },
        account_data={"type": ACCOUNT_DATA_TYPE, "content": ACCOUNT_DATA_CONTENT},
        pusher=PUSHER,
    )
    return result


# ---------------------------------------------------------------------------
# Per-backend runs
# ---------------------------------------------------------------------------


def run_backend(
    release: OldRelease, scratch: pathlib.Path, name: str, master_key: pathlib.Path, database_lines: list[str]
) -> tuple[dict[str, Any], pathlib.Path]:
    work = scratch / name
    work.mkdir()
    client_port, fed_port = free_port(), free_port()
    config = write_config(work, release, master_key, client_port, fed_port, database_lines)
    log(f"[{name}] starting {release.server.name} {release.version}")
    handle = start_server(release, config, work, client_port)
    api = Api(client_port)
    try:
        result = run_scenario(api)
    except BaseException:
        handle.process.kill()
        handle.process.wait()
        print(handle.log_path.read_text(errors="replace")[-6000:], file=sys.stderr)
        raise
    code = stop_server(handle)
    log(f"[{name}] server exit code after SIGTERM: {code}")
    if code != 0:
        raise FixtureError(f"[{name}] server exited with {code} after SIGTERM, not 0")
    result["http_log"] = api.calls
    result["non_2xx"] = [c for c in api.calls if not 200 <= c["status"] < 300]
    result["server_exit_code"] = code
    return result, work


# schema_migrations.version is a TEXT column in both backends, so max(version) would compare
# lexicographically ('9' > '11'); always cast before aggregating.
def finalise_sqlite(db_path: pathlib.Path, expected_version: int) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        integrity = conn.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise FixtureError(f"sqlite integrity_check: {integrity!r}")
        top = conn.execute("SELECT max(CAST(version AS INTEGER)) FROM schema_migrations").fetchone()[0]
        if top != expected_version:
            raise FixtureError(f"sqlite schema version {top}, expected {expected_version}")
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        side = pathlib.Path(str(db_path) + suffix)
        if side.exists() and side.stat().st_size > 0:
            raise FixtureError(f"{side.name} still holds data after checkpoint")


def dump_postgres(cluster: PgCluster, out_sql: pathlib.Path, expected_version: int) -> None:
    dumped = run([cluster.tool("pg_dump"), "-h", "127.0.0.1", "-p", str(cluster.port), "-U", PG_ROLE,
                  "--no-owner", "--no-privileges", "--no-comments", "--column-inserts", PG_DATABASE])
    kept = [line for line in dumped.stdout.splitlines() if not line.startswith("\\")]
    text = "\n".join(kept) + "\n"
    if re.search(r"^COPY ", text, re.MULTILINE):
        raise FixtureError("pg_dump output contains COPY blocks")
    out_sql.write_text(text, encoding="utf-8")

    restore_db = f"{PG_DATABASE}_restore"
    admin = [cluster.tool("psql"), "-h", "127.0.0.1", "-p", str(cluster.port), "-U", "postgres", "-X", "-d",
             "postgres", "-c"]
    run([*admin, f"DROP DATABASE IF EXISTS {restore_db}"])
    run([*admin, f"CREATE DATABASE {restore_db} OWNER {PG_ROLE} TEMPLATE template0 ENCODING 'UTF8'"])
    run([cluster.tool("psql"), "-h", "127.0.0.1", "-p", str(cluster.port), "-U", PG_ROLE, "-d", restore_db, "-X",
         "-q", "-v", "ON_ERROR_STOP=1", "-f", str(out_sql)])
    top = cluster.psql(restore_db, "-c", "SELECT max(CAST(version AS INTEGER)) FROM schema_migrations").stdout.strip()
    log(f"postgresql dump restored into a fresh database; schema_migrations max version = {top}")
    if top != str(expected_version):
        raise FixtureError(f"restored postgresql schema version {top}, expected {expected_version}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("commit", help="old release commit to build and run")
    parser.add_argument("output_dir", type=pathlib.Path, help="directory that receives the three fixture files")
    parser.add_argument("--checkout-dir", type=pathlib.Path,
                        help="Linux-native directory for the old checkout and build "
                             "(default: ~/merovingian-upgrade-fixture/<commit>)")
    parser.add_argument("--source-repo", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent.parent,
                        help="repository to clone the old commit from (default: this repository)")
    parser.add_argument("--pg-bin-dir", help="directory holding initdb, pg_ctl, psql, pg_dump")
    args = parser.parse_args()

    checkout = args.checkout_dir or pathlib.Path.home() / "merovingian-upgrade-fixture" / args.commit
    pg_bin = find_pg_bin_dir(args.pg_bin_dir)
    release = prepare_old_release(args.source_repo, args.commit, checkout.expanduser().resolve())
    log(f"old release {release.version} at {release.commit}, schema version {release.schema_version}")

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    master_key_bytes = os.urandom(32)
    manifest: dict[str, Any] = {
        "release": release.version,
        "commit": release.commit,
        "schema_version": release.schema_version,
        "server_name": SERVER_NAME,
        "master_key_hex": master_key_bytes.hex(),
        "registration_token": REGISTRATION_TOKEN,
    }

    with tempfile.TemporaryDirectory(prefix="merovingian-fixture-") as scratch_name:
        scratch = pathlib.Path(scratch_name)
        master_key = scratch / "master-key"
        write_secret(master_key, master_key_bytes)

        # SQLite -----------------------------------------------------------
        sqlite_path = scratch / "sqlite-data" / "merovingian.sqlite3"
        sqlite_path.parent.mkdir()
        sqlite_result, _ = run_backend(release, scratch, "sqlite", master_key,
                                       ["database.backend=sqlite", f"database.sqlite_path={sqlite_path}"])
        finalise_sqlite(sqlite_path, release.schema_version)
        shutil.copyfile(sqlite_path, out / "merovingian.sqlite3")
        manifest["sqlite"] = sqlite_result

        # PostgreSQL -------------------------------------------------------
        with throwaway_postgres(pg_bin, scratch) as cluster:
            uri_file = scratch / "db-uri"
            write_secret(uri_file, cluster.uri().encode())
            pg_result, _ = run_backend(release, scratch, "postgresql", master_key,
                                       ["database.backend=postgresql", f"database.uri_file={uri_file}",
                                        "database.role=runtime", "database.pool_size=4"])
            dump_postgres(cluster, out / "postgresql.sql", release.schema_version)
            manifest["postgresql"] = pg_result

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    log(f"wrote {out}")
    for backend in ("sqlite", "postgresql"):
        for call in manifest[backend]["non_2xx"]:
            log(f"[{backend}] non-2xx: {call}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FixtureError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
