# Main judges relayed events against its own room server ACL

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-24 (`fed.send-shard-hint-stale-room-acl`)

## Context and Problem Statement

A `/send` transaction is routed to a worker shard by the room of its first PDU, a string the sender chooses.
Only the shard that owns a room is told when the room changes (`room_sync`), so any other shard holds the room
as it was when that worker started. The per-PDU server ACL check
(`room_server_acl_provider`, spec "Server Access Control Lists (ACLs)": a PDU from a denied server "MUST be ignored
with an appropriate error included in the response for the respective event ID") ran on that stale snapshot, and
main's `pdu_ingest` handler did not repeat it. A denied server could pick the shard whose snapshot lacked the ACL.

## Decision Outcome

Main judges the ACL itself. `handle_pdu_ingest_request`, `handle_membership_ingest_request` and
`handle_invite_ingest_request` read `room_server_acl_allows` from main's store, under `runtime.mutex`:

* for the transport origin the frame names, before any key is looked up (and before the already-stored shortcut,
  as in `/send`);
* for the server the verified event's sender belongs to, for `pdu_ingest` and `membership_ingest`, once the event
  is verified. The spec's endpoint list protects `send_join`, `send_leave`, `send_knock` and `invite` for the
  sending server, and `/send` for each PDU's sender, so an invite is judged by its origin only.

A refused PDU answers with the new `PduIngestionStatus::rejected_acl`, which `/send` reports as an `error` entry for the
event ID (as its own ACL check does) and which is not stored or counted against the origin's trust. A refused
membership or invite relay answers 403. `load_room_server_acl` reads the current `m.room.server_acl` through the
state index (`find_current_state_event_id`, ADR-0344), so the check costs a hash lookup under the mutex, not a scan of
all state.

A status of its own, and not `rejected_auth`: a rejection is stored and the transaction carries no error for it,
which is the opposite of what the spec asks for an ACL refusal.

### Negative Consequences

* A relay reads the ACL twice (the worker's snapshot, then main's). The worker's check stays: it spares main the IPC
  and the signature work in the common case.
* The origin in the frame is the worker's claim (ADR-0358). The sender check does not depend on it.

## Links

* Related to [ADR-0358](0358-main-applies-the-admin-federation-policy-to-every-verified-request.md) and
  [ADR-0360](0360-the-worker-guards-its-store-with-a-reader-writer-lock-taken-only-for-the-swap.md)
