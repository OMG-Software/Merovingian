# Room versions 1 and 2 are not supported

* Status: accepted
* Date: 2026-09-28

Technical Story: finding "Room versions 1 and 2: event_id-domain signature"
recorded in `docs/todos/capability-gaps.md` on the 0.12.13 branch. The option
below was chosen in writing by the user on 2026-09-28.

## Context and Problem Statement

The room version registry listed versions 1 and 2 as stable, so they were
advertised in `m.room_versions`, accepted by `createRoom`, offered in the
`ver` list of outbound `make_join`, and used to parse inbound PDUs. None of
what makes them different was implemented:

* Their event ID is carried in the event as `$localpart:domain`
  (rooms/v1.md); the server computed a reference-hash ID for every version,
  so every v1/v2 event got the wrong ID.
* "Room versions 1 and 2 also require that a signature is present from the
  domain in the `event_id`, if it differs from the originating server"
  (server-server-api.md) — never checked.
* Version 1 has its own state resolution algorithm; the resolver treated it
  as v2.

The spec lets a server choose which versions it supports: the
`m.room_versions` capability lists "The room versions the server supports",
and `createRoom` answers an unsupported one with `M_UNSUPPORTED_ROOM_VERSION`.

## Considered Options

* Stop supporting v1 and v2.
* Implement v1 and v2 fully: event IDs from the event on every inbound path,
  their grammar, the event-ID-domain signature, locally minted
  `$localpart:domain` IDs, and v1 state resolution.
* Fix inbound parsing and the signature check only, refusing to create or
  join v1/v2 rooms.

## Decision Outcome

Chosen option: "Stop supporting v1 and v2".

* Both are removed from `rooms::policies`, with the enum values only they
  used (`EventFormat::room_v1_v2`, `StateResolutionAlgorithm::v1`).
  `find_room_version_policy` returns null for them, so every path refuses
  them: `createRoom` (400 `M_UNSUPPORTED_ROOM_VERSION`), the capability list,
  the outbound `make_join` `ver` list, inbound PDUs, and invites.
* An invite into an unsupported version answers 400
  `M_INCOMPATIBLE_ROOM_VERSION` with `room_version`, as the v2 invite endpoint
  defines. A v1 invite for a room whose version is not known locally implies
  version 1 or 2 ("Servers which receive a v1 invite request must assume that
  the room version is either 1 or 2") and is refused the same way.

Do not add either version back without implementing everything listed in the
context above.

### Positive Consequences

* No code path handles events whose IDs and signatures it cannot compute or
  check correctly.

### Negative Consequences

* Users of this server cannot join or be invited to v1/v2 rooms. Such rooms
  could not have worked here before either.

## Pros and Cons of the Options

### Stop supporting v1 and v2

* Good, because it removes an unverifiable attack surface outright and is
  small.
* Bad, because v1/v2 rooms that still exist elsewhere are unreachable.

### Implement v1 and v2 fully

* Good, because every stable version would work.
* Bad, because it touches every event-ID computation and adds a state
  resolution algorithm, for versions that are rarely used.

### Inbound only

* Good, because it closes the signature gap for received events.
* Bad, because it leaves a half-supported version that can be received but
  not created or joined.

## Links

* Spec: [rooms/v1.md](../matrix-v1.19-spec/rooms/v1.md),
  [rooms/v2.md](../matrix-v1.19-spec/rooms/v2.md)
* Spec: [client-server-api.md, `m.room_versions` capability and
  `POST /createRoom`](../matrix-v1.19-spec/client-server-api.md)
