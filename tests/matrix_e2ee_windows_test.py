#!/usr/bin/env python3
"""
Windows-native Matrix v1.18 E2EE two-user smoke test.

Why this exists:
    Native Python Matrix E2EE commonly depends on python-olm/libolm, which is
    not a reliable native Windows install path. This runner is still a Python
    test client, but it uses Node.js + matrix-js-sdk's Rust-Crypto WASM backend
    for the actual Olm/Megolm cryptography. That keeps the encrypted Matrix
    traffic real while avoiding native libolm builds on Windows.

What it does:
    1. Registers two fresh users.
    2. Starts two Matrix clients with Rust-Crypto E2EE enabled.
    3. Creates an encrypted DM room using m.megolm.v1.aes-sha2.
    4. Invites Bob; Bob joins.
    5. Sends encrypted m.room.message events both ways.
    6. Verifies each receiver gets a decrypted message and that the wire event
       was m.room.encrypted where observable.
    7. Logs both users out.

Prerequisites on Windows:
    - Python 3.10+
    - Node.js LTS 20+ or 22+
    - npm available on PATH

First run:
    python matrix_e2ee_windows_test.py --homeserver http://127.0.0.1:8008 --log-level debug

Registration-token homeserver:
    python matrix_e2ee_windows_test.py --homeserver http://127.0.0.1:8008 --registration-token TOKEN --log-level debug

Keep generated Node project/log artifacts:
    python matrix_e2ee_windows_test.py --homeserver http://127.0.0.1:8008 --keep-workdir --log-level debug
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable


NODE_HELPER = r"""
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const sdk = require("matrix-js-sdk");

function now() {
    return new Date().toISOString();
}

let config = {};

function log(level, msg, fields = {}) {
    const rec = Object.assign({ ts: now(), level, msg }, fields);
    console.log(JSON.stringify(rec));
}

function debug(msg, fields = {}) {
    if (config.logLevel === "debug") log("debug", msg, fields);
}

function info(msg, fields = {}) {
    log("info", msg, fields);
}

function warn(msg, fields = {}) {
    log("warn", msg, fields);
}

function error(msg, fields = {}) {
    log("error", msg, fields);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function lowerLocalpart(prefix) {
    const allowed = new Set("abcdefghijklmnopqrstuvwxyz0123456789._=-/+");
    let out = "";
    for (const ch of prefix.toLowerCase()) {
        if (allowed.has(ch)) out += ch;
    }
    out = out.replace(/^[._=\-/+]+|[._=\-/+]+$/g, "");
    if (!out) out = "e2ee";
    return `${out}_${crypto.randomBytes(5).toString("hex")}`;
}

function clientUrl(baseUrl, pathPart) {
    return `${baseUrl.replace(/\/+$/, "")}${pathPart}`;
}

async function matrixRequest(method, pathPart, body, accessToken = null) {
    const headers = { "content-type": "application/json" };
    if (accessToken) headers.authorization = `Bearer ${accessToken}`;

    const requestId = crypto.randomBytes(4).toString("hex");
    debug("http_request", { requestId, method, path: pathPart, body: body ? redactBody(body) : null });

    const res = await fetch(clientUrl(config.homeserver, pathPart), {
        method,
        headers,
        body: body === undefined || body === null ? undefined : JSON.stringify(body),
    });

    const text = await res.text();
    let json = {};
    if (text.length > 0) {
        try {
            json = JSON.parse(text);
        } catch (e) {
            throw new Error(`${method} ${pathPart} returned non-JSON HTTP ${res.status}: ${text.slice(0, 500)}`);
        }
    }

    debug("http_response", { requestId, status: res.status, body: redactBody(json) });

    if (!res.ok) {
        const err = new Error(`${method} ${pathPart} failed HTTP ${res.status}: ${JSON.stringify(redactBody(json))}`);
        err.status = res.status;
        err.body = json;
        throw err;
    }
    return json;
}

function redactBody(obj) {
    if (obj === null || obj === undefined) return obj;
    if (Array.isArray(obj)) return obj.map(redactBody);
    if (typeof obj !== "object") return obj;

    const redacted = {};
    for (const [k, v] of Object.entries(obj)) {
        if (["access_token", "password", "token"].includes(k)) {
            redacted[k] = "<redacted>";
        } else if (k === "auth" && v && typeof v === "object") {
            redacted[k] = redactBody(v);
        } else {
            redacted[k] = redactBody(v);
        }
    }
    return redacted;
}

async function registerAccount(label, localpart, password, deviceId, deviceDisplayName) {
    info("register_start", { label, localpart, deviceId });

    const registerPath = "/_matrix/client/v3/register";
    const base = {
        username: localpart,
        password,
        device_id: deviceId,
        initial_device_display_name: deviceDisplayName,
        inhibit_login: false,
    };

    async function attempt(auth) {
        const body = Object.assign({}, base);
        if (auth) body.auth = auth;
        try {
            return await matrixRequest("POST", registerPath, body);
        } catch (e) {
            if (e.status === 401 && e.body && (e.body.flows || e.body.session)) return e.body;
            throw e;
        }
    }

    let first = await attempt({ type: "m.login.dummy" });

    if (first && first.access_token) {
        info("register_ok", { label, userId: first.user_id, deviceId: first.device_id });
        return first;
    }

    if (!first.session) {
        throw new Error(`${label}: registration returned UIA response without session: ${JSON.stringify(redactBody(first))}`);
    }

    const flows = first.flows || [];
    const stages = new Set();
    for (const flow of flows) for (const stage of (flow.stages || [])) stages.add(stage);

    info("register_uia_required", { label, session: first.session, stages: Array.from(stages) });

    let afterToken = first;
    if (stages.has("m.login.registration_token")) {
        if (!config.registrationToken) {
            throw new Error(`${label}: homeserver requires m.login.registration_token but --registration-token was not supplied`);
        }
        afterToken = await attempt({
            type: "m.login.registration_token",
            token: config.registrationToken,
            session: first.session,
        });
        if (afterToken && afterToken.access_token) {
            info("register_ok", { label, userId: afterToken.user_id, deviceId: afterToken.device_id });
            return afterToken;
        }
    }

    const session = (afterToken && afterToken.session) || first.session;
    const finalResp = await matrixRequest("POST", registerPath, Object.assign({}, base, {
        auth: { type: "m.login.dummy", session },
    }));

    info("register_ok", { label, userId: finalResp.user_id, deviceId: finalResp.device_id });
    return finalResp;
}

async function loginAccount(label, localpart, password, deviceId, deviceDisplayName) {
    info("login_start", { label, localpart, deviceId });
    const resp = await matrixRequest("POST", "/_matrix/client/v3/login", {
        type: "m.login.password",
        identifier: { type: "m.id.user", user: localpart },
        password,
        device_id: deviceId,
        initial_device_display_name: deviceDisplayName,
    });
    info("login_ok", { label, userId: resp.user_id, deviceId: resp.device_id });
    return resp;
}

async function registerOrLogin(label, localpart, password, deviceId, deviceDisplayName) {
    try {
        return await registerAccount(label, localpart, password, deviceId, deviceDisplayName);
    } catch (e) {
        if (!config.useExisting) throw e;
        warn("register_failed_use_existing_login", { label, error: e.message });
        return await loginAccount(label, localpart, password, deviceId, deviceDisplayName);
    }
}

function makeClient(label, auth) {
    const client = sdk.createClient({
        baseUrl: config.homeserver,
        accessToken: auth.access_token,
        userId: auth.user_id,
        deviceId: auth.device_id,
        timelineSupport: true,
        cryptoCallbacks: {
            getSecretStorageKey: async () => {
                throw new Error("Secret storage is not expected in this fresh two-user smoke test");
            },
        },
    });

    client.__label = label;
    client.__seenMessages = [];
    client.__syncStates = [];

    client.on("sync", (state, prevState, data) => {
        client.__syncStates.push({ state, prevState, nextBatch: data && data.nextBatch });
        debug("sync_state", { label, state, prevState, nextBatch: data && data.nextBatch });
    });

    client.on("event", (event) => {
        const wireType = safeCall(() => event.getWireType && event.getWireType());
        const type = safeCall(() => event.getType && event.getType());
        debug("client_event", {
            label,
            type,
            wireType,
            sender: safeCall(() => event.getSender && event.getSender()),
            eventId: safeCall(() => event.getId && event.getId()),
        });
    });

    client.on("Room.timeline", async (event, room, toStartOfTimeline) => {
        try {
            if (toStartOfTimeline) return;

            const wireTypeBefore = safeCall(() => event.getWireType && event.getWireType());
            const typeBefore = safeCall(() => event.getType && event.getType());
            const encryptedBefore = Boolean(safeCall(() => event.isEncrypted && event.isEncrypted()));

            if (encryptedBefore) {
                try {
                    await client.decryptEventIfNeeded(event);
                } catch (e) {
                    warn("timeline_decrypt_failed", {
                        label,
                        roomId: room && room.roomId,
                        eventId: safeCall(() => event.getId && event.getId()),
                        sender: safeCall(() => event.getSender && event.getSender()),
                        error: e.message,
                    });
                }
            }

            const typeAfter = safeCall(() => event.getType && event.getType());
            const content = safeCall(() => event.getContent && event.getContent()) || {};
            const clearContent = safeCall(() => event.getClearContent && event.getClearContent()) || content;
            const body = clearContent.body || content.body;
            const msgtype = clearContent.msgtype || content.msgtype;
            const encryptedAfter = Boolean(safeCall(() => event.isEncrypted && event.isEncrypted()));
            const isDecryptionFailure = Boolean(safeCall(() => event.isDecryptionFailure && event.isDecryptionFailure()));

            info("timeline_event", {
                label,
                roomId: room && room.roomId,
                eventId: safeCall(() => event.getId && event.getId()),
                sender: safeCall(() => event.getSender && event.getSender()),
                typeBefore,
                typeAfter,
                wireType: wireTypeBefore,
                encryptedBefore,
                encryptedAfter,
                isDecryptionFailure,
                msgtype,
                body,
            });

            if (typeAfter === "m.room.message" && msgtype === "m.text" && typeof body === "string") {
                client.__seenMessages.push({
                    roomId: room.roomId,
                    eventId: safeCall(() => event.getId && event.getId()),
                    sender: safeCall(() => event.getSender && event.getSender()),
                    body,
                    wireType: wireTypeBefore,
                    encrypted: encryptedBefore || encryptedAfter || wireTypeBefore === "m.room.encrypted",
                    decryptionFailure: isDecryptionFailure,
                });
            }
        } catch (e) {
            error("timeline_callback_error", { label, error: e.stack || e.message });
        }
    });

    return client;
}

function safeCall(fn) {
    try {
        return fn();
    } catch (e) {
        return undefined;
    }
}

async function initClientCrypto(client) {
    info("init_rust_crypto_start", { label: client.__label, userId: client.getUserId(), deviceId: client.getDeviceId() });
    await client.initRustCrypto({ useIndexedDB: false });
    info("init_rust_crypto_ok", { label: client.__label });
}

async function startAndWaitPrepared(client) {
    info("start_client", { label: client.__label });
    await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error(`${client.__label}: timed out waiting for sync PREPARED`));
        }, config.timeoutMs);

        client.once("sync", (state) => {
            if (state === "ERROR") {
                clearTimeout(timeout);
                reject(new Error(`${client.__label}: sync entered ERROR`));
            }
        });

        const handler = (state, prev, data) => {
            if (state === "PREPARED") {
                client.removeListener("sync", handler);
                clearTimeout(timeout);
                info("client_prepared", { label: client.__label, nextBatch: data && data.nextBatch });
                resolve();
            }
        };

        client.on("sync", handler);
        client.startClient({ initialSyncLimit: 20, pollTimeout: 1000, lazyLoadMembers: false });
    });
}

async function waitUntil(description, predicate, pump, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    let attempts = 0;
    while (Date.now() < deadline) {
        attempts += 1;
        if (await predicate()) {
            info("wait_ok", { description, attempts });
            return;
        }
        if (pump) await pump();
        await sleep(250);
    }
    throw new Error(`Timed out waiting for ${description}`);
}

async function createEncryptedRoom(alice, bobUserId) {
    info("create_encrypted_room_start", { label: alice.__label, invite: bobUserId });
    const resp = await alice.createRoom({
        invite: [bobUserId],
        is_direct: true,
        initial_state: [{
            type: "m.room.encryption",
            state_key: "",
            content: { algorithm: "m.megolm.v1.aes-sha2" },
        }],
    });
    info("create_encrypted_room_ok", { roomId: resp.room_id });
    return resp.room_id;
}

async function waitRoomKnown(client, roomId) {
    await waitUntil(
        `${client.__label} knows room ${roomId}`,
        async () => Boolean(client.getRoom(roomId)),
        null,
        config.timeoutMs,
    );
    const room = client.getRoom(roomId);
    info("room_known", {
        label: client.__label,
        roomId,
        membership: room && room.getMyMembership && room.getMyMembership(),
        hasEncryptionStateEvent: Boolean(room && room.hasEncryptionStateEvent && room.hasEncryptionStateEvent()),
    });
}

async function waitRoomEncrypted(client, roomId) {
    await waitUntil(
        `${client.__label} sees encryption enabled in ${roomId}`,
        async () => {
            const room = client.getRoom(roomId);
            if (room && room.hasEncryptionStateEvent && room.hasEncryptionStateEvent()) return true;
            const cryptoApi = client.getCrypto && client.getCrypto();
            if (cryptoApi && cryptoApi.isEncryptionEnabledInRoom) {
                return await cryptoApi.isEncryptionEnabledInRoom(roomId);
            }
            return false;
        },
        null,
        config.timeoutMs,
    );
    info("room_encrypted", { label: client.__label, roomId });
}

async function joinRoom(client, roomId) {
    info("join_room_start", { label: client.__label, roomId });
    const resp = await client.joinRoom(roomId);
    info("join_room_ok", { label: client.__label, roomId: resp.roomId || roomId });
}

async function waitJoined(client, roomId) {
    await waitUntil(
        `${client.__label} joined ${roomId}`,
        async () => {
            const room = client.getRoom(roomId);
            return Boolean(room && (!room.getMyMembership || room.getMyMembership() === "join"));
        },
        null,
        config.timeoutMs,
    );
    info("room_joined", { label: client.__label, roomId });
}

async function downloadKeys(client, users) {
    if (typeof client.downloadKeysForUsers === "function") {
        info("download_keys_start", { label: client.__label, users });
        await client.downloadKeysForUsers(users, true);
        info("download_keys_ok", { label: client.__label, users });
    } else if (typeof client.downloadKeys === "function") {
        info("download_keys_start", { label: client.__label, users });
        await client.downloadKeys(users, true);
        info("download_keys_ok", { label: client.__label, users });
    } else {
        warn("download_keys_not_available", { label: client.__label });
    }
}

async function sendAndWait(sender, receiver, roomId, body) {
    info("send_start", { from: sender.__label, to: receiver.__label, roomId, body });
    const txnId = sender.makeTxnId ? sender.makeTxnId() : `m${Date.now()}${Math.random()}`;
    const resp = await sender.sendEvent(roomId, "m.room.message", {
        msgtype: "m.text",
        body,
    }, txnId);
    info("send_ok", { from: sender.__label, eventId: resp.event_id, txnId });

    await waitUntil(
        `${receiver.__label} receives decrypted encrypted message ${body}`,
        async () => receiver.__seenMessages.some(m =>
            m.roomId === roomId &&
            m.sender === sender.getUserId() &&
            m.body === body &&
            m.encrypted === true &&
            m.decryptionFailure === false
        ),
        null,
        config.timeoutMs,
    );

    const msg = receiver.__seenMessages.find(m =>
        m.roomId === roomId &&
        m.sender === sender.getUserId() &&
        m.body === body
    );
    info("receive_verified", {
        receiver: receiver.__label,
        sender: sender.getUserId(),
        eventId: msg && msg.eventId,
        wireType: msg && msg.wireType,
        encrypted: msg && msg.encrypted,
        body,
    });
}

async function logoutClient(client) {
    try {
        info("logout_start", { label: client.__label, userId: client.getUserId(), deviceId: client.getDeviceId() });
        client.stopClient();
        await client.logout();
        info("logout_ok", { label: client.__label });
    } catch (e) {
        warn("logout_failed", { label: client.__label, error: e.message });
    }
}

async function main() {
    const configPath = process.argv[2];
    if (!configPath) throw new Error("Usage: node matrix_e2ee_js_helper.cjs <config.json>");
    config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    config.timeoutMs = Math.floor((config.timeoutSeconds || 45) * 1000);

    info("helper_start", {
        node: process.version,
        matrixJsSdk: require("matrix-js-sdk/package.json").version,
        homeserver: config.homeserver,
        timeoutMs: config.timeoutMs,
    });

    const runId = crypto.randomBytes(4).toString("hex");
    const password = config.password || `test-password-${crypto.randomBytes(18).toString("base64url")}`;

    const aliceLocalpart = config.aliceLocalpart || lowerLocalpart(`${config.usernamePrefix || "e2ee_test"}_alice`);
    const bobLocalpart = config.bobLocalpart || lowerLocalpart(`${config.usernamePrefix || "e2ee_test"}_bob`);
    const aliceDeviceId = config.aliceDeviceId || `WINALICE${runId.toUpperCase()}`;
    const bobDeviceId = config.bobDeviceId || `WINBOB${runId.toUpperCase()}`;

    let alice = null;
    let bob = null;

    try {
        const aliceAuth = await registerOrLogin("alice", aliceLocalpart, password, aliceDeviceId, "windows-e2ee-test alice");
        const bobAuth = await registerOrLogin("bob", bobLocalpart, password, bobDeviceId, "windows-e2ee-test bob");

        alice = makeClient("alice", aliceAuth);
        bob = makeClient("bob", bobAuth);

        await initClientCrypto(alice);
        await initClientCrypto(bob);

        await startAndWaitPrepared(alice);
        await startAndWaitPrepared(bob);

        await downloadKeys(alice, [alice.getUserId(), bob.getUserId()]);
        await downloadKeys(bob, [alice.getUserId(), bob.getUserId()]);

        const roomId = await createEncryptedRoom(alice, bob.getUserId());
        await waitRoomKnown(alice, roomId);
        await waitRoomEncrypted(alice, roomId);

        await waitRoomKnown(bob, roomId);
        await joinRoom(bob, roomId);
        await waitJoined(bob, roomId);
        await waitRoomEncrypted(bob, roomId);

        await downloadKeys(alice, [alice.getUserId(), bob.getUserId()]);
        await downloadKeys(bob, [alice.getUserId(), bob.getUserId()]);

        const aliceBody = `encrypted hello from alice ${runId}`;
        const bobBody = `encrypted hello from bob ${runId}`;

        await sendAndWait(alice, bob, roomId, aliceBody);
        await sendAndWait(bob, alice, roomId, bobBody);

        info("success", {
            roomId,
            aliceUserId: alice.getUserId(),
            aliceDeviceId: alice.getDeviceId(),
            bobUserId: bob.getUserId(),
            bobDeviceId: bob.getDeviceId(),
        });
    } finally {
        if (alice) await logoutClient(alice);
        if (bob) await logoutClient(bob);
    }
}

process.on("unhandledRejection", (reason) => {
    error("unhandled_rejection", { error: reason && (reason.stack || reason.message || String(reason)) });
    process.exitCode = 1;
});

main().catch((e) => {
    error("fatal", { error: e.stack || e.message });
    process.exit(1);
});
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Windows-native Matrix v1.18 two-user E2EE smoke test client",
    )
    parser.add_argument("--homeserver", required=True, help="Homeserver URL, e.g. http://127.0.0.1:8008")
    parser.add_argument("--registration-token", help="Registration token for token-protected registration")
    parser.add_argument("--username-prefix", default="e2ee_test", help="Prefix for generated localparts")
    parser.add_argument("--alice-localpart", help="Fixed Alice localpart; default is generated")
    parser.add_argument("--bob-localpart", help="Fixed Bob localpart; default is generated")
    parser.add_argument("--password", help="Password for both users; default is generated")
    parser.add_argument("--alice-device-id", help="Fixed Alice device ID")
    parser.add_argument("--bob-device-id", help="Fixed Bob device ID")
    parser.add_argument("--use-existing", action="store_true", help="If registration fails, try logging in with the supplied localparts/password")
    parser.add_argument("--workdir", help="Directory for the generated Node project; default is a temporary directory")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep generated Node project and helper files")
    parser.add_argument("--skip-npm-install", action="store_true", help="Do not run npm install; useful when reusing --workdir")
    parser.add_argument("--timeout", type=float, default=45.0, help="Seconds to wait for each async Matrix condition")
    parser.add_argument("--log-level", choices=["info", "debug"], default="info", help="Log verbosity")
    parser.add_argument("--matrix-js-sdk-version", default="latest", help='npm version for matrix-js-sdk, default "latest"')
    return parser.parse_args()


def run_command(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"[python] running in {cwd}: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line.rstrip(), flush=True)
    rc = proc.wait()
    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)


def check_executable(name: str, version_args: Iterable[str]) -> None:
    cmd = [name, *version_args]
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except Exception as exc:
        raise SystemExit(
            f"Required executable {name!r} was not found or could not run. "
            f"Install Node.js LTS and ensure {name!r} is on PATH. Details: {exc}"
        ) from exc
    print(f"[python] {name} detected: {completed.stdout.strip()}", flush=True)


def write_node_project(workdir: Path, matrix_js_sdk_version: str) -> tuple[Path, Path]:
    workdir.mkdir(parents=True, exist_ok=True)

    package_json = {
        "name": "matrix-e2ee-windows-test",
        "private": True,
        "type": "commonjs",
        "dependencies": {
            "matrix-js-sdk": matrix_js_sdk_version,
        },
    }

    package_path = workdir / "package.json"
    helper_path = workdir / "matrix_e2ee_js_helper.cjs"

    package_path.write_text(json.dumps(package_json, indent=2), encoding="utf-8")
    helper_path.write_text(NODE_HELPER, encoding="utf-8")
    return package_path, helper_path


def write_config(args: argparse.Namespace, workdir: Path) -> Path:
    config = {
        "homeserver": args.homeserver.rstrip("/"),
        "registrationToken": args.registration_token,
        "usernamePrefix": args.username_prefix,
        "aliceLocalpart": args.alice_localpart,
        "bobLocalpart": args.bob_localpart,
        "password": args.password,
        "aliceDeviceId": args.alice_device_id,
        "bobDeviceId": args.bob_device_id,
        "useExisting": args.use_existing,
        "timeoutSeconds": args.timeout,
        "logLevel": args.log_level,
    }
    config_path = workdir / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def main() -> int:
    args = parse_args()

    check_executable("node", ["--version"])
    check_executable("npm", ["--version"])

    temp_root: tempfile.TemporaryDirectory[str] | None = None
    if args.workdir:
        workdir = Path(args.workdir).resolve()
    else:
        temp_root = tempfile.TemporaryDirectory(prefix="matrix-e2ee-win-")
        workdir = Path(temp_root.name).resolve()

    print(f"[python] workdir: {workdir}", flush=True)

    try:
        _, helper_path = write_node_project(workdir, args.matrix_js_sdk_version)

        if not args.skip_npm_install:
            run_command(["npm", "install", "--no-audit", "--no-fund"], cwd=workdir)

        config_path = write_config(args, workdir)
        run_command(["node", str(helper_path), str(config_path)], cwd=workdir)

        print("[python] SUCCESS", flush=True)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[python] FAILED: command exited {exc.returncode}: {' '.join(exc.cmd)}", file=sys.stderr, flush=True)
        return exc.returncode or 1
    except Exception as exc:
        print(f"[python] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        if args.keep_workdir:
            print(f"[python] keeping workdir: {workdir}", flush=True)
        elif temp_root is not None:
            temp_root.cleanup()
        elif args.workdir and not args.keep_workdir:
            # User-supplied workdir is not removed by default.
            print(f"[python] leaving user-supplied workdir in place: {workdir}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
