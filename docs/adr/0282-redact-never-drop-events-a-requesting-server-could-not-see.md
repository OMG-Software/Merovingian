# Redact, never drop, room events a requesting server could not see

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: Complement run 10 follow-up (server-level history visibility)

## Context and Problem Statement

The Server-Server API v1.19 defines no history visibility between servers. `/event`, `/backfill` and
`/get_missing_events` sent every event they reached, in full, to any server that passed the in-room
gate (`origin_may_read_room`): a server whose only user joined today could read a `joined`-visibility
room's earlier history. The client-server spec's "Room History Visibility" defines the four settings
for users only. The owner decided (2026-10-29) that events a requesting server could not see are sent
redacted.

## Considered Options

* Drop the events the requesting server could not see.
* Send them as the room version's redaction of the stored event.
* Filter state (`/state`, `/state_ids`, `/event_auth`) the same way.

## Decision Outcome

Chosen option: redact, per event, on `/event`, `/backfill` and `/get_missing_events`, using the
X-Matrix-authenticated origin and the room state recorded for the event (its ADR-0064 state group,
never current state).

* `world_readable` and `shared` (the default when no setting exists): the full event.
* `invited`: full when a user of the origin is invited or joined in that state.
* `joined`: full when a user of the origin is joined in that state.
* Otherwise the event is `events::redact_event` of the stored event; signatures, hashes,
  `prev_events`, `auth_events` and the event ID are untouched, and nothing is dropped from the walk.
* The state used is the state after the event (its state group), so a history-visibility event is
  judged under the setting it carries and the join or invite of the origin's own user is visible to
  it. The state before it would need `state_transitions`, which a federation worker does not hold.
* Fail closed: an event with no state group or a broken group chain is redacted; one that cannot be
  redacted (unknown room version) is omitted, never sent in full.
* `/state`, `/state_ids` and `/event_auth` are not filtered. State is the room's authorisation
  record; a joining or catching-up server must hold it whole to compute state and authorise events.
  A future read that returns room events goes through `ServerEventFilter`; filtering state needs
  another ADR.

Dropping events was rejected because it leaves holes in the receiver's graph that
`/get_missing_events` would never fill. Filtering state was rejected because a joining server could
then not authorise events against the room's real state.

### Negative Consequences

* A receiver gets redacted copies whose signatures verify but whose content hash does not; the spec
  tells it to redact and continue (receipt step 3).
* Outliers and any history without a state group are served redacted, whatever the room's setting.
* Each request builds the state-group indexes once, as `sync::HistoryVisibility` does for client
  reads.
