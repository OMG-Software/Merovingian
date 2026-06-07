#!/usr/bin/env python3
"""
Matrix v1.18 E2EE two-user smoke-test client.

Registers two users, obtains authenticated device sessions, creates an encrypted
DM room, sends encrypted messages both ways, verifies that each recipient
decrypts the message, and logs out.

Dependencies:
    python -m pip install "matrix-nio[e2e]" aiofiles

Example:
    python matrix_e2ee_two_user_test.py \
        --homeserver http://127.0.0.1:8008 \
        --store-root ./nio-test-store \
        --log-level DEBUG

Notes:
    * Registration uses Matrix dummy auth by default. For servers requiring
      registration tokens, pass --registration-token.
    * The test uses a controlled, out-of-band trust decision: after both fresh
      test accounts publish device keys, each client pins and verifies the
      other user's known device ID. This avoids disabling verification while
      still permitting a deterministic automated test.
    * For servers with self-signed TLS certificates, pass --insecure. Do not use
      --insecure against production servers.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import logging
import os
import secrets
import shutil
import string
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

try:
    from nio import (
        AsyncClient,
        ClientConfig,
        InviteEvent,
        JoinResponse,
        LoginResponse,
        LogoutResponse,
        MatrixRoom,
        RegisterResponse,
        RoomCreateResponse,
        RoomInviteResponse,
        RoomMessageText,
        RoomSendResponse,
        RoomPutStateResponse,
        SyncResponse,
        exceptions,
    )
except ImportError as exc:  # pragma: no cover - diagnostic path for test hosts.
    raise SystemExit(
        "Missing dependency. Install with:\n"
        '    python -m pip install "matrix-nio[e2e]" aiofiles\n'
        f"Original import error: {exc}"
    ) from exc


LOG = logging.getLogger("matrix-e2ee-test")


@dataclasses.dataclass(frozen=True)
class Account:
    label: str
    localpart: str
    password: str
    device_name: str
    store_path: Path
    client: AsyncClient
    user_id: str = ""
    device_id: str = ""


@dataclasses.dataclass
class SeenMessage:
    client_label: str
    room_id: str
    sender: str
    body: str
    decrypted: bool
    event_id: Optional[str]


class MessageRecorder:
    def __init__(self) -> None:
        self.messages: list[SeenMessage] = []

    async def callback(self, room: MatrixRoom, event: RoomMessageText) -> None:
        seen = SeenMessage(
            client_label=getattr(room, "own_user_id", "") or "<unknown-client>",
            room_id=room.room_id,
            sender=event.sender,
            body=event.body,
            decrypted=bool(getattr(event, "decrypted", False)),
            event_id=getattr(event, "event_id", None),
        )
        self.messages.append(seen)
        LOG.info(
            "event_callback: room=%s sender=%s decrypted=%s event_id=%s body=%r",
            seen.room_id,
            seen.sender,
            seen.decrypted,
            seen.event_id,
            seen.body,
        )

    def find(self, *, room_id: str, sender: str, body: str, require_decrypted: bool) -> Optional[SeenMessage]:
        for msg in self.messages:
            if msg.room_id != room_id:
                continue
            if msg.sender != sender:
                continue
            if msg.body != body:
                continue
            if require_decrypted and not msg.decrypted:
                continue
            return msg
        return None


def valid_localpart(prefix: str) -> str:
    # Matrix v1.18 new user localparts are lowercase a-z, digits, and selected
    # punctuation. Keep this deliberately conservative for broad server support.
    suffix = secrets.token_hex(5)
    cleaned = "".join(ch for ch in prefix.lower() if ch in string.ascii_lowercase + string.digits + "._=-/+")
    cleaned = cleaned.strip("._=-/+")
    if not cleaned:
        cleaned = "e2ee"
    return f"{cleaned}_{suffix}"


def response_debug(resp: Any) -> str:
    attrs = []
    for name in ("user_id", "device_id", "room_id", "event_id", "next_batch", "status_code", "message", "transport_response"):
        if hasattr(resp, name):
            value = getattr(resp, name)
            if name == "transport_response" and value is not None:
                value = f"HTTP {getattr(value, 'status', '<unknown>')}"
            attrs.append(f"{name}={value!r}")
    return f"{resp.__class__.__name__}({', '.join(attrs)})"


def is_error_response(resp: Any) -> bool:
    name = resp.__class__.__name__
    if name.endswith("Error") or name.endswith("ErrorResponse"):
        return True
    # nio ErrorResponse-like objects generally expose a status_code/message pair.
    if hasattr(resp, "message") and hasattr(resp, "status_code") and not isinstance(
        resp,
        (
            LoginResponse,
            RegisterResponse,
            SyncResponse,
            RoomCreateResponse,
            RoomSendResponse,
            JoinResponse,
            LogoutResponse,
            RoomInviteResponse,
            RoomPutStateResponse,
        ),
    ):
        return True
    return False


def assert_ok(resp: Any, operation: str, expected_type: Optional[type] = None) -> Any:
    LOG.debug("%s -> %s", operation, response_debug(resp))
    if expected_type is not None and not isinstance(resp, expected_type):
        raise RuntimeError(f"{operation} failed: expected {expected_type.__name__}, got {response_debug(resp)}")
    if is_error_response(resp):
        raise RuntimeError(f"{operation} failed: {response_debug(resp)}")
    return resp


async def log_response(resp: Any) -> None:
    if is_error_response(resp):
        LOG.warning("response_callback: %s", response_debug(resp))
    else:
        LOG.debug("response_callback: %s", response_debug(resp))


async def log_invite(room: MatrixRoom, event: InviteEvent) -> None:
    LOG.info(
        "invite_callback: room_id=%s inviter=%s state_key=%s",
        room.room_id,
        getattr(event, "sender", None),
        getattr(event, "state_key", None),
    )


def make_client(homeserver: str, user: str, device_id: str, store_path: Path, insecure: bool) -> AsyncClient:
    store_path.mkdir(parents=True, exist_ok=True)
    config = ClientConfig(store_sync_tokens=True)
    client = AsyncClient(
        homeserver=homeserver.rstrip("/"),
        user=user,
        device_id=device_id,
        store_path=str(store_path),
        config=config,
        ssl=False if insecure else None,
    )
    client.add_response_callback(log_response)
    return client


async def register_or_login(
    *,
    account: Account,
    registration_token: Optional[str],
    use_existing: bool,
) -> Account:
    client = account.client
    LOG.info("[%s] registering localpart=%s device_name=%r store=%s", account.label, account.localpart, account.device_name, account.store_path)

    if registration_token:
        resp = await client.register_with_token(
            account.localpart,
            account.password,
            registration_token,
            device_name=account.device_name,
        )
    else:
        resp = await client.register(
            account.localpart,
            account.password,
            device_name=account.device_name,
        )

    if isinstance(resp, RegisterResponse):
        assert_ok(resp, f"{account.label}: register", RegisterResponse)
        LOG.info("[%s] registered and authenticated: user_id=%s device_id=%s", account.label, resp.user_id, resp.device_id)
        return dataclasses.replace(account, user_id=resp.user_id, device_id=resp.device_id)

    if not use_existing:
        raise RuntimeError(f"{account.label}: registration failed: {response_debug(resp)}")

    LOG.warning("[%s] registration failed; --use-existing set, attempting password login: %s", account.label, response_debug(resp))
    login = await client.login(password=account.password, device_name=account.device_name)
    assert_ok(login, f"{account.label}: login", LoginResponse)
    LOG.info("[%s] logged in: user_id=%s device_id=%s", account.label, login.user_id, login.device_id)
    return dataclasses.replace(account, user_id=login.user_id, device_id=login.device_id)


async def sync_once(client: AsyncClient, label: str, *, timeout_ms: int = 0, full_state: Optional[bool] = None) -> SyncResponse:
    LOG.debug("[%s] sync start timeout_ms=%s full_state=%s", label, timeout_ms, full_state)
    resp = await client.sync(timeout=timeout_ms, full_state=full_state, set_presence="offline")
    assert_ok(resp, f"{label}: sync", SyncResponse)
    LOG.debug("[%s] sync ok next_batch=%s", label, resp.next_batch)
    return resp


async def maybe_upload_keys(client: AsyncClient, label: str) -> None:
    should = bool(getattr(client, "should_upload_keys", False))
    LOG.debug("[%s] should_upload_keys=%s", label, should)
    if not should:
        return
    try:
        resp = await client.keys_upload()
    except Exception as exc:
        raise RuntimeError(f"{label}: keys_upload raised {type(exc).__name__}: {exc}") from exc
    assert_ok(resp, f"{label}: keys_upload")
    LOG.info("[%s] uploaded E2EE device/one-time keys", label)


async def maybe_query_keys(client: AsyncClient, label: str) -> None:
    should = bool(getattr(client, "should_query_keys", False))
    users = list(getattr(client, "users_for_key_query", []) or [])
    LOG.debug("[%s] should_query_keys=%s users_for_key_query=%s", label, should, users)
    if not should:
        return
    try:
        resp = await client.keys_query()
    except Exception as exc:
        raise RuntimeError(f"{label}: keys_query raised {type(exc).__name__}: {exc}") from exc
    assert_ok(resp, f"{label}: keys_query")
    LOG.info("[%s] queried device keys for users=%s", label, users)


async def pump_client(client: AsyncClient, label: str, *, rounds: int = 1, timeout_ms: int = 0, full_state_first: bool = False) -> None:
    for i in range(rounds):
        await sync_once(client, label, timeout_ms=timeout_ms, full_state=full_state_first if i == 0 else None)
        await maybe_upload_keys(client, label)
        await maybe_query_keys(client, label)


async def wait_until(
    description: str,
    predicate: Callable[[], bool],
    pump: Callable[[], Any],
    timeout_s: float,
    interval_s: float = 0.2,
) -> None:
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if predicate():
            LOG.info("wait ok: %s attempts=%d", description, attempt)
            return
        await pump()
        if predicate():
            LOG.info("wait ok after pump: %s attempts=%d", description, attempt)
            return
        await asyncio.sleep(interval_s)
    raise TimeoutError(f"timed out waiting for {description}")


def room_status(client: AsyncClient, room_id: str) -> str:
    room = client.rooms.get(room_id)
    if room is None:
        return "room=<missing>"
    return (
        f"room_id={room.room_id} encrypted={room.encrypted} "
        f"members_synced={getattr(room, 'members_synced', None)} "
        f"users={sorted(list(getattr(room, 'users', {}).keys()))}"
    )


def dump_device_store(client: AsyncClient, label: str, users: Iterable[str]) -> None:
    LOG.info("[%s] device store dump:", label)
    store = getattr(client, "device_store", None)
    if store is None:
        LOG.info("[%s]   no device_store attribute", label)
        return

    for user_id in users:
        try:
            devices = store[user_id]
        except Exception:
            LOG.info("[%s]   %s: <not present>", label, user_id)
            continue

        for device_id, device in devices.items():
            LOG.info(
                "[%s]   %s %s trust=%s display=%r curve=%s ed=%s",
                label,
                user_id,
                device_id,
                getattr(device, "trust_state", None),
                getattr(device, "display_name", None),
                getattr(device, "curve25519", None),
                getattr(device, "ed25519", None),
            )


async def wait_for_device(client: AsyncClient, label: str, user_id: str, device_id: str, timeout_s: float) -> None:
    async def pump() -> None:
        await pump_client(client, label, rounds=1, timeout_ms=1000, full_state_first=False)

    def present() -> bool:
        try:
            return device_id in client.device_store[user_id]
        except Exception:
            return False

    await wait_until(f"{label} sees device {user_id}/{device_id}", present, pump, timeout_s)
    LOG.info("[%s] sees expected device: %s/%s", label, user_id, device_id)


def verify_expected_device(client: AsyncClient, label: str, user_id: str, device_id: str) -> None:
    try:
        device = client.device_store[user_id][device_id]
    except Exception as exc:
        raise RuntimeError(f"{label}: cannot verify missing device {user_id}/{device_id}") from exc

    LOG.info("[%s] verifying pinned device out-of-band: %s/%s", label, user_id, device_id)
    client.verify_device(device)


async def create_encrypted_room(alice: Account, bob: Account) -> str:
    LOG.info("[alice] creating encrypted DM room and inviting %s", bob.user_id)
    content = {
        "algorithm": "m.megolm.v1.aes-sha2",
    }
    initial_state = [
        {
            "type": "m.room.encryption",
            "state_key": "",
            "content": content,
        }
    ]
    resp = await alice.client.room_create(
        invite=[bob.user_id],
        is_direct=True,
        initial_state=initial_state,
    )
    assert_ok(resp, "alice: room_create encrypted DM", RoomCreateResponse)
    LOG.info("[alice] room created: room_id=%s", resp.room_id)
    return resp.room_id


async def wait_for_room(client: AsyncClient, label: str, room_id: str, timeout_s: float, *, encrypted: bool) -> None:
    async def pump() -> None:
        await pump_client(client, label, rounds=1, timeout_ms=1000, full_state_first=True)

    def ready() -> bool:
        room = client.rooms.get(room_id)
        return bool(room and ((not encrypted) or room.encrypted))

    await wait_until(f"{label} has room {room_id} encrypted={encrypted}", ready, pump, timeout_s)
    LOG.info("[%s] room ready: %s", label, room_status(client, room_id))


async def join_invited_room(bob: Account, room_id: str, timeout_s: float) -> None:
    async def pump() -> None:
        await pump_client(bob.client, bob.label, rounds=1, timeout_ms=1000, full_state_first=True)

    def invited() -> bool:
        return room_id in bob.client.invited_rooms or room_id in bob.client.rooms

    await wait_until(f"bob sees invite for {room_id}", invited, pump, timeout_s)

    if room_id in bob.client.rooms:
        LOG.info("[bob] already joined room: %s", room_status(bob.client, room_id))
        return

    LOG.info("[bob] joining invited room %s", room_id)
    resp = await bob.client.join(room_id)
    assert_ok(resp, "bob: join", JoinResponse)
    await wait_for_room(bob.client, bob.label, room_id, timeout_s, encrypted=True)


async def send_and_wait(
    *,
    sender: Account,
    recipient: Account,
    recorder: MessageRecorder,
    room_id: str,
    body: str,
    timeout_s: float,
) -> None:
    LOG.info("[%s] sending encrypted message to %s: %r", sender.label, recipient.label, body)
    try:
        resp = await sender.client.room_send(
            room_id=room_id,
            message_type="m.room.message",
            content={"msgtype": "m.text", "body": body},
            ignore_unverified_devices=False,
        )
    except exceptions.OlmUnverifiedDeviceError:
        LOG.error("[%s] refusing to send because at least one device is unverified", sender.label)
        dump_device_store(sender.client, sender.label, [sender.user_id, recipient.user_id])
        raise

    assert_ok(resp, f"{sender.label}: room_send encrypted", RoomSendResponse)
    LOG.info("[%s] send ok event_id=%s", sender.label, resp.event_id)

    async def pump_recipient() -> None:
        await pump_client(recipient.client, recipient.label, rounds=1, timeout_ms=1000, full_state_first=False)

    def received() -> bool:
        return recorder.find(
            room_id=room_id,
            sender=sender.user_id,
            body=body,
            require_decrypted=True,
        ) is not None

    await wait_until(f"{recipient.label} receives decrypted message {body!r}", received, pump_recipient, timeout_s)
    msg = recorder.find(room_id=room_id, sender=sender.user_id, body=body, require_decrypted=True)
    LOG.info(
        "[%s] decrypted message received: event_id=%s sender=%s body=%r",
        recipient.label,
        msg.event_id if msg else None,
        sender.user_id,
        body,
    )


async def logout_account(account: Account) -> None:
    LOG.info("[%s] logging out device_id=%s", account.label, account.device_id)
    try:
        resp = await account.client.logout(all_devices=False)
        assert_ok(resp, f"{account.label}: logout", LogoutResponse)
        LOG.info("[%s] logout ok", account.label)
    except Exception:
        LOG.exception("[%s] logout failed", account.label)
        raise
    finally:
        await account.client.close()


async def run(args: argparse.Namespace) -> None:
    run_id = secrets.token_hex(4)
    password = args.password or f"test-password-{secrets.token_urlsafe(18)}"

    if args.alice_localpart:
        alice_localpart = args.alice_localpart
    else:
        alice_localpart = valid_localpart(f"{args.username_prefix}_alice")

    if args.bob_localpart:
        bob_localpart = args.bob_localpart
    else:
        bob_localpart = valid_localpart(f"{args.username_prefix}_bob")

    store_root = Path(args.store_root).resolve()
    if store_root.exists() and not args.keep_store:
        LOG.info("removing existing store root: %s", store_root)
        shutil.rmtree(store_root)
    store_root.mkdir(parents=True, exist_ok=True)

    alice_store = store_root / f"alice-{run_id}"
    bob_store = store_root / f"bob-{run_id}"

    alice_client = make_client(
        args.homeserver,
        alice_localpart,
        args.alice_device_id or f"AUTOALICE{run_id.upper()}",
        alice_store,
        args.insecure,
    )
    bob_client = make_client(
        args.homeserver,
        bob_localpart,
        args.bob_device_id or f"AUTOB0B{run_id.upper()}",
        bob_store,
        args.insecure,
    )

    recorder_alice = MessageRecorder()
    recorder_bob = MessageRecorder()
    alice_client.add_event_callback(recorder_alice.callback, RoomMessageText)
    bob_client.add_event_callback(recorder_bob.callback, RoomMessageText)
    alice_client.add_event_callback(log_invite, InviteEvent)
    bob_client.add_event_callback(log_invite, InviteEvent)

    alice = Account("alice", alice_localpart, password, "matrix-e2ee-test alice", alice_store, alice_client)
    bob = Account("bob", bob_localpart, password, "matrix-e2ee-test bob", bob_store, bob_client)

    try:
        LOG.info("homeserver=%s insecure_tls=%s run_id=%s", args.homeserver, args.insecure, run_id)
        LOG.info("store_root=%s keep_store=%s", store_root, args.keep_store)

        alice = await register_or_login(account=alice, registration_token=args.registration_token, use_existing=args.use_existing)
        bob = await register_or_login(account=bob, registration_token=args.registration_token, use_existing=args.use_existing)

        # First sync and E2EE key publication for both devices.
        await pump_client(alice.client, alice.label, rounds=2, timeout_ms=0, full_state_first=True)
        await pump_client(bob.client, bob.label, rounds=2, timeout_ms=0, full_state_first=True)

        room_id = await create_encrypted_room(alice, bob)

        await wait_for_room(alice.client, alice.label, room_id, args.timeout, encrypted=True)
        await join_invited_room(bob, room_id, args.timeout)
        await wait_for_room(bob.client, bob.label, room_id, args.timeout, encrypted=True)

        # Ensure both clients have current membership and key-query tracking.
        await pump_client(alice.client, alice.label, rounds=2, timeout_ms=0, full_state_first=True)
        await pump_client(bob.client, bob.label, rounds=2, timeout_ms=0, full_state_first=True)

        await wait_for_device(alice.client, alice.label, bob.user_id, bob.device_id, args.timeout)
        await wait_for_device(bob.client, bob.label, alice.user_id, alice.device_id, args.timeout)

        dump_device_store(alice.client, alice.label, [alice.user_id, bob.user_id])
        dump_device_store(bob.client, bob.label, [alice.user_id, bob.user_id])

        verify_expected_device(alice.client, alice.label, bob.user_id, bob.device_id)
        verify_expected_device(bob.client, bob.label, alice.user_id, alice.device_id)

        dump_device_store(alice.client, alice.label, [alice.user_id, bob.user_id])
        dump_device_store(bob.client, bob.label, [alice.user_id, bob.user_id])

        alice_body = f"encrypted hello from alice {run_id}"
        bob_body = f"encrypted hello from bob {run_id}"

        await send_and_wait(
            sender=alice,
            recipient=bob,
            recorder=recorder_bob,
            room_id=room_id,
            body=alice_body,
            timeout_s=args.timeout,
        )
        await send_and_wait(
            sender=bob,
            recipient=alice,
            recorder=recorder_alice,
            room_id=room_id,
            body=bob_body,
            timeout_s=args.timeout,
        )

        LOG.info("SUCCESS: two users registered/authenticated, exchanged decrypted E2EE messages both ways, and will now logout")
    finally:
        errors = []
        for account in (alice, bob):
            if getattr(account.client, "access_token", None):
                with contextlib.suppress(Exception):
                    await logout_account(account)
            else:
                with contextlib.suppress(Exception):
                    await account.client.close()
        if not args.keep_store:
            with contextlib.suppress(Exception):
                shutil.rmtree(store_root)
                LOG.info("removed store root: %s", store_root)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Matrix v1.18 two-user E2EE automated test client")
    parser.add_argument("--homeserver", required=True, help="Homeserver base URL, e.g. http://127.0.0.1:8008")
    parser.add_argument("--registration-token", help="Registration token for m.login.registration_token, if required")
    parser.add_argument("--username-prefix", default="e2ee_test", help="Prefix used for generated localparts")
    parser.add_argument("--alice-localpart", help="Use a fixed Alice localpart instead of generating one")
    parser.add_argument("--bob-localpart", help="Use a fixed Bob localpart instead of generating one")
    parser.add_argument("--password", help="Password to use for both accounts. Default: random strong password")
    parser.add_argument("--alice-device-id", help="Fixed Alice device ID")
    parser.add_argument("--bob-device-id", help="Fixed Bob device ID")
    parser.add_argument("--use-existing", action="store_true", help="If registration fails, try password login with the supplied/generated localparts")
    parser.add_argument("--store-root", default="./matrix-e2ee-test-store", help="Directory for nio crypto stores")
    parser.add_argument("--keep-store", action="store_true", help="Keep nio stores after completion/failure for inspection")
    parser.add_argument("--timeout", type=float, default=30.0, help="Seconds to wait for each async condition")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation")
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"), choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s.%(msecs)03d %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Keep library loggers useful but not overwhelming unless DEBUG is requested.
    if level != "DEBUG":
        logging.getLogger("nio").setLevel(logging.INFO)
        logging.getLogger("aiohttp").setLevel(logging.WARNING)


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)
    try:
        asyncio.run(run(args))
        return 0
    except Exception:
        LOG.exception("FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
