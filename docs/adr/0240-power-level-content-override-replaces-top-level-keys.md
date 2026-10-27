# power_level_content_override replaces top-level keys

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement `TestDemotingUsersViaUsersDefault`, which 0.12.59's v12 tombstone level
broke.

## Context and Problem Statement

`POST /createRoom` takes `power_level_content_override`, which "is applied on top of the generated
`m.room.power_levels` event content prior to it being sent to the room." The spec does not say
how deep "on top of" goes. This server merged the override into the generated content
recursively, so `"events": {}` left the generated `events` map, and its new v12
`m.room.tombstone` level, in place. Complement's test overrides `events` with `{}` and then
expects a user at level 100 to send power levels with `"events": {}`; with the tombstone kept at
150 the auth rules refuse that. The same test lists the room creator in its override `users` map
for rooms below version 12, which only matters if that map replaces the generated one: that is how
Synapse applies the override (a dictionary update).

Should an override key replace the generated key, or merge into it?

## Decision Drivers

* The spec does not settle it; the owner decides (2026-10-27).
* The spec lets clients override the v12 tombstone level through this field, so a client must be
  able to remove it.
* Behaving as the reference implementation and the conformance suite expect, where the spec allows
  it.

## Considered Options

* Replace: each key of the override replaces that key of the generated content, nested maps
  (`users`, `events`, `notifications`) included.
* Merge recursively, as before.

## Decision Outcome

Chosen option: replace. The v12 `m.room.tombstone` level (150) is part of the generated `events`
map, so an override that supplies `events` decides it, and one that does not keeps it above the
resulting `state_default`. Creators are still never left in a v12 `users` map, and an override
naming one is refused before anything is created (`M_INVALID_ROOM_STATE`).

### Positive Consequences

* A client can drop or change the tombstone level, as the spec says it may.
* `createRoom` with an override behaves as it does on Synapse, which clients are written against.

### Negative Consequences

* Below room version 12, an override `users` map that leaves out the creator leaves the creator
  without its generated level 100; the rest of the room's initial state is then sent by a user who
  may lack the power to send it. That is the client's request, as on Synapse.
* `POST /rooms/{roomId}/upgrade` passes the old room's power levels as the override, so they now
  arrive whole rather than merged into the defaults.
