# Stamp v12 create events with a strictly increasing timestamp, stepping past taken room IDs

* Status: accepted
* Date: 2026-10-16

Technical Story: the conformance scenario "GET /sync returns spec-shaped room category objects" failed
intermittently (2 of 20 isolated runs in a release build) with `POST /createRoom` answering 500.

## Context and Problem Statement

In room version 12 the room ID is the create event's reference hash
([rooms/v12.md](../matrix-v1.19-spec/rooms/v12.md): "The room ID is the event ID of the event with sigil
`!` instead of `$`."). A v12 create event carries no `room_id` and no `prev_events`; its depth is always
1. What varies between two create events from one user is the content and `origin_server_ts`, and Ed25519
signing is deterministic. Two `createRoom` requests from one user with the same creation content in the
same millisecond therefore composed byte-identical create events and derived the same room ID. The second
request failed on the duplicate `rooms` row and answered 500, logged only at debug level.

The spec says `createRoom` will "Create a new room", and its only responses are 200 and 400. Each request
must get a new room of its own.

## Considered Options

* **Stamp each create event strictly after the last one this runtime composed, and step past a timestamp
  whose room ID is already taken (chosen).**
* Add a random value to the create event's content. Rejected: it invents a content key the spec does not
  define, signed into every v12 room this server creates and carried to every server in the room for its
  lifetime, to solve a problem the spec's own varying field already solves.
* Retry when storing the room row fails. Rejected: by then the policy-server hook has run for the
  colliding room ID with `runtime.mutex` released, and a failed store does not say why it failed, so a
  retry would recompose after a decision taken for a different room.
* Answer with the existing room's ID. Rejected: it hands the caller a room it did not create, against
  "Create a new room".

## Decision Outcome

Chosen option: in `create_room`, for room versions whose create event defines the room ID:

* The create event's `origin_server_ts` is `max(clock, last_create_event_ts_ms + 1)`, where
  `HomeserverRuntime::last_create_event_ts_ms` (guarded by `runtime.mutex`) is the timestamp of the
  previous create event this runtime composed. It is reserved before the policy-server hook releases the
  mutex, so concurrent requests get different timestamps.
* If the derived room ID already exists (in `persistent_store.rooms` or `database.rooms`) the timestamp
  is moved on by one millisecond and the event recomposed. After a restart the runtime has no memory of
  earlier timestamps and the clock may have been stepped back, so the counter alone is not enough. Each
  existing room blocks at most one timestamp, so `rooms + 1` attempts always find a free ID.

Do not go back to stamping the create event with the bare clock reading. `compose_signed_event` still
uses the clock for every other event: their `prev_events` and `depth` already make them distinct.

### Positive Consequences

* Back-to-back `createRoom` calls never collide, whether from a fast client, a script or a test.
* No content beyond what the spec defines is signed into the create event.

### Negative Consequences

* A burst of N room creations within one millisecond stamps the last one up to N-1 ms in the future.
  That is far inside the tolerance any server applies to `origin_server_ts`.

## Links

* Test seam: `HomeserverRuntime::test_frozen_event_clock_ms` freezes the event clock, which is how the
  conformance scenario "POST /createRoom creates a distinct room for each request made within one
  millisecond" reproduces the collision deterministically.
