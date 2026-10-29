# The room version resolver does not guess for unknown rooms

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10, F1 (`TestIsDirectFlagFederation`,
`TestMSC4311RejectInvalidStrippedStateFederation`)

## Context and Problem Statement

`runtime.federation.room_version_resolver` maps a room ID to its version from
the stored `m.room.create`. For a room this server held no create event for, it
answered `"10"`. Every caller had its own fallback for an unknown room: a relayed
invite takes the version the invite declares, a v1 invite the spec's "1 or 2",
and `/send` parses as v12. None of them ever ran, because the resolver never
answered "unknown".

Main re-verifies an invite a federation worker relays (ADR-0071). For an invite
into a room main does not hold, it verified the sender's signature under v10
redaction. v10 keeps the top-level `origin` key, which v11 and later strip.
Servers built on gomatrixserverlib (Synapse, Dendrite, Complement) set `origin`,
so their invites into v11 and v12 rooms failed main's check with "signature by a
known key does not verify". This server's own events carry no `origin`, so
invites between two Merovingian servers passed.

## Considered Options

* Keep the resolver's `"10"`, and make the invite relay read the stored version
  itself, falling back to the declared one.
* Have the resolver answer an empty string for an unknown room, and let each
  caller apply its own fallback.

## Decision Outcome

Chosen option: the resolver answers an empty string for a room with no stored
create, because the guess was wrong for every caller that already stated what
it wanted for an unknown room. With the first option, the next caller to treat
`"10"` as a real answer repeats the bug.

Rules for code that uses the resolver:

* An empty answer means "this server does not hold the room". Handle it at the
  call site: `parse_federation_pdu` and `parse_inbound_pdu_envelope` take `"12"`,
  the worker's `/invite` handler takes the declared version (or `"1"` for a v1
  invite), and main's relay takes the version the frame declares.
* Never give the resolver a default version again. A version for an unknown room
  is a choice each caller makes for its own reason.

### Positive Consequences

* A relayed invite into a room main does not hold is verified under the version
  it declares, the only version information there is.
* The worker's v1 invite path now reaches the spec's "1 or 2" assumption and
  answers `M_INCOMPATIBLE_ROOM_VERSION`, as its comment always said it did.

### Negative Consequences

* A `/send` PDU for an unknown room is now parsed as v12 rather than v10 before
  room-interest admission refuses it (FED-11). Its computed event ID differs
  from before; nothing stores it.
