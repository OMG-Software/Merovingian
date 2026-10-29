# invite_room_state is validated for room versions 12 and up only

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestMSC4311FullEventsOnStrippedStateFederation`,
`TestMSC4311RejectInvalidStrippedStateFederation`, `TestMSC4311StrippedStateClientAPI`)

## Context and Problem Statement

Since v1.16, `invite_room_state` and `knock_room_state` are lists of full PDUs that MUST contain the
room's `m.room.create`. Our outbound invites sent `{}` and our `send_knock` answers sent nothing. The
`PUT /v2/invite` description says servers SHOULD validate the list for room versions 12 and up, and
MAY for versions 1 through 11, answering `M_INVALID_PARAM`.

## Considered Options

* Validate every room version.
* Validate room versions 12 and up only.

## Decision Outcome

Chosen option: versions 12 and up only, because servers still migrating send stripped entries in older
rooms, and refusing those invites would break federation the spec still allows.

* `validate_invite_room_state` refuses a missing create event, an entry that is not a version-formatted
  PDU, an entry in another room (a v12 create's room is `!` plus its reference hash), an entry whose
  signature fails, and more than 16 entries. Signatures go through the admitted key lookup; a lookup
  refused for local load is 503, not a verdict.
* It runs in the worker's `/invite` handler and in main's `invite_ingest` relay: the state travels in the
  relayed frame, and main never takes the worker's word (ADR-0071).
* Outbound invites and `send_knock` answers send the stored signed PDUs of the stripped-state types,
  create first (`homeserver::stripped_state_pdus`).
* Do not extend the check to versions 1 through 11, and do not drop it for 12 as redundant with the
  invite's own signature check: it is the state entries that are being checked.
