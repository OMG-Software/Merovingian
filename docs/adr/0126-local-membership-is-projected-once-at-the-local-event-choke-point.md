# Local membership is projected once, at the local-event choke point

* Status: accepted
* Date: 2026-10-08

Technical Story: 29 September 2026 security audit, finding CSAZ-6 (membership changes sent through
`PUT /state/m.room.member` skip the membership projection).

## Context and Problem Statement

A user's membership lives in two places: the room's state (the current `m.room.member` event, which the
authorization rules read) and the projections built from it, the `memberships` rows and
`LocalRoom.members`, which the read gates, `/joined_rooms`, `/joined_members` and `join_room` trust. Only
the membership APIs (`/invite`, `/kick`, `/ban`, `/leave`, `/join`, `createRoom`) updated the projections,
each in its own code. A ban sent as a state event (`PUT /state/m.room.member/{userId}`, which the spec
allows: "It is preferable to use the membership APIs ... rather than adjusting the state directly")
changed the state and nothing else, so the banned user stayed listed as joined and could rejoin, because
`join_room` saw a member and returned early.

Where should a locally created `m.room.member` event become the user's membership?

## Considered Options

* **In `persist_composed_event`, the ADR-0064 choke point every locally composed event is stored
  through, and only when the event is now the current state for its user (chosen).**
* In each endpoint. Rejected: this is what failed; the state API is one more endpoint, and the next one
  added would be missed in the same way.
* In `PersistentStore`'s post-store observer (the CSAZ-11 redaction hook, ADR-0125). Rejected: it sees
  every stored event, including backfilled, outlier and auth-chain events, and an old member event
  arriving by backfill would overwrite the user's current membership. The projection follows current
  state, not arrival.

## Decision Outcome

Chosen option: `project_local_membership` in `src/homeserver/room_service.cpp`, called by
`persist_composed_event` for every `m.room.member` event it stores.

* It projects only when the room's current state for `(m.room.member, state_key)` now names this event,
  so an event state resolution did not pick is not the user's membership.
* It writes the `memberships` row, updates `LocalRoom.members`, records device-list share changes on a
  transition into or out of `join` (spec, "Tracking the device list for a user"), and upserts or clears
  invite metadata.
* **Rule for future code: callers do not repeat any of this.** `persist_membership_transition`,
  `join_room` and `createRoom`'s invites used to; a second projection allocates a second stream ordering
  and can record duplicate device-list changes.
* Read access is unchanged and is decided by resolved state (ADR-0084): a banned or kicked user reads as
  of the event that ended their join, as the spec's history visibility rules require ("After a user has
  left a room, they may see any events which they were allowed to see before they left the room, but no
  events received after they left").

Membership arriving over federation keeps its own projection in the ingest path, which already follows
current state; this decision covers events this server composes.

### Negative Consequences

* A projection failure now fails the store of the event that caused it, so an endpoint that used to
  report a specific error ("membership persistence failed") reports the generic persistence failure.
