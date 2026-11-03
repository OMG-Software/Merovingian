#!/usr/bin/env python3
"""The routing table for outbound federation calls (F-43, ADR-0349).

The federation worker is the process most exposed to hostile traffic, so what it
relays is input. An outbound answer main uses without checking a signature must
come over main's own OutboundClient. Every caller of the perform_*_outbound_call
family names its OutboundAnswerTrust, and this test pins which callers may say
`signature_verified`: only those whose every use of a success body is a
signature check on the whole of it.

Adding a caller to the verified list is a trust decision. Do it in ADR-0349's
table and here, in the same change.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = REPO_ROOT / "src"

CALL = re.compile(
    r"(?<!auto )\bperform_(?:sync_|bounded_)?outbound_call(?:_with_status)?\(\s*"
    r"(?P<args>[^;]*?\"(?P<event>[a-z_.]+)\"[^;]*?)\)\s*;",
    re.S,
)
TRUST = re.compile(r"OutboundAnswerTrust::(?P<trust>unverified|signature_verified)")

# The diagnostic event of each call whose answer main verifies by signature, as
# `federation.backfill.*`: each PDU is verified (signature, content hash, auth)
# one by one before it is stored, and a failure only means "no data".
VERIFIED_EVENTS = {
    "federation.backfill.get_missing_events_failed",
    "federation.backfill.event_fetch_failed",
    "federation.backfill.snapshot_event_fetch_failed",
    "federation.backfill.event_auth_failed",
}

# Every call in the table, so a caller added or removed shows up as a failure here
# and is classified on purpose rather than by default.
EXPECTED_EVENTS = VERIFIED_EVENTS | {
    "key_query.remote",
    "key_claim.remote",
    "profile.proxy",
    "public_rooms.proxy",
    "directory.room.proxy",
    "room.join.alias_lookup_failed",
    "federation.backfill.state_ids_failed",
    "timestamp_to_event.ask",
    "space_hierarchy.fetch",
    "room.join.remote.make_join_failed",
    "room.join.remote.send_join_failed",
    "room.leave.remote.make_leave_failed",
    "room.leave.remote.send_leave_failed",
    "room.invite.remote_failed",
    "room.knock.remote.make_knock_failed",
    "room.knock.remote.send_knock_failed",
}


def classified_calls() -> dict[str, list[str]]:
    """Map each call's diagnostic event to the trust(s) its call sites name."""
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_DIR.rglob("*.cpp")):
        text = path.read_text(encoding="utf-8")
        for match in CALL.finditer(text):
            trust = TRUST.search(match.group("args"))
            found.setdefault(match.group("event"), []).append(trust.group("trust") if trust else "NONE")
    return found


class OutboundAnswerTrustTable(unittest.TestCase):
    def test_every_caller_names_its_trust(self) -> None:
        calls = classified_calls()
        missing = {event: trusts for event, trusts in calls.items() if "NONE" in trusts}
        self.assertEqual(missing, {}, "a caller of the outbound call family does not name its OutboundAnswerTrust")

    def test_the_table_holds_every_caller_and_no_other(self) -> None:
        self.assertEqual(set(classified_calls()), EXPECTED_EVENTS)

    def test_only_signature_checked_callers_are_signature_verified(self) -> None:
        verified = {
            event
            for event, trusts in classified_calls().items()
            if "signature_verified" in trusts
        }
        self.assertEqual(verified, VERIFIED_EVENTS)

    def test_no_caller_is_both(self) -> None:
        mixed = {
            event: trusts
            for event, trusts in classified_calls().items()
            if len(set(trusts)) > 1
        }
        self.assertEqual(mixed, {})

    def test_the_worker_route_is_reached_only_for_signature_verified_answers(self) -> None:
        text = (SOURCE_DIR / "homeserver" / "room_service.cpp").read_text(encoding="utf-8")
        self.assertIn("auto const via_worker = trust == OutboundAnswerTrust::signature_verified;", text)
        # Nothing else may hand a request to the tunnel.
        senders = [
            path.relative_to(REPO_ROOT).as_posix()
            for path in sorted(SOURCE_DIR.rglob("*.cpp"))
            if "federation_proxy->send_outbound_request" in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(senders, ["src/homeserver/room_service.cpp"])
        self.assertEqual(text.count("federation_proxy->send_outbound_request"), 1)
        gate = text.index("else if (via_worker && runtime.federation_proxy)")
        self.assertLess(gate, text.index("federation_proxy->send_outbound_request"))


if __name__ == "__main__":
    unittest.main()
