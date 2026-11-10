# State content checks run in one place for every local writer

* Status: accepted
* Date: 2026-11-09

Technical Story: Security audit run 4, F-19.

## Context and Problem Statement

The spec asks a server to check the content of an `m.room.canonical_alias` event (new aliases valid, and pointing at the
room) and requires `m.room.encryption` to name `m.megolm.v1.aes-sha2`. The checks lived in the `PUT /state` branch of the
client dispatcher, so `POST /rooms/{roomId}/send` with a `state_key` and `createRoom` `initial_state` stored the same
events unchecked. Where should the checks live so no local writer can skip them?

## Considered Options

* Copy the checks into each writer.
* Check in the client dispatcher for each route.
* Check in `send_event_as_user` (every body-typed local send, which `PUT /state` and `PUT /send` reach too) and in
  `create_room` for `initial_state`, both calling `state_content_refusal`.

## Decision Outcome

Chosen option: the third. `state_content_refusal` (`state_content_check.cpp`) is the only place the content is judged.
`send_event_as_user` calls it after the power check (`may_send_state_event`), so a sender who may not send the event still
gets the authorization 403, and only for a state event with the empty state key: a message event of the type, or a state
event under another key, is not judged. `create_room` calls it for `m.room.canonical_alias` entries of `initial_state`
before anything is stored, passing the alias the same request creates (`room_alias_name`) as `pending_alias`, because the
room and the alias do not exist when the state is judged.

`createRoom` does not judge `m.room.encryption` with this function. [ADR-0445](0445-room-creation-encryption-is-decided-only-by-the-encryption-policy.md) decides an `initial_state`
encryption entry: an entry that is not `m.megolm.v1.aes-sha2` is the documented way to ask for an unencrypted room, refused
with `M_INVALID_ROOM_STATE` by default and allowed where the operator's encryption settings say so. Judging it here too
would make the operator setting unreachable. A refused alias in `createRoom` is also `M_INVALID_ROOM_STATE`, the code the
spec gives for "the initial state implied by the parameters to the request is invalid"; `PUT /state` and `POST /send` keep
`M_INVALID_PARAM`, `M_BAD_ALIAS` and `M_BAD_JSON`.

### Negative Consequences

* A room created with the operator's explicit-unencrypted setting can still hold an `m.room.encryption` event whose
  algorithm is not megolm; that is ADR-0445's decision, not a gap in this one.
