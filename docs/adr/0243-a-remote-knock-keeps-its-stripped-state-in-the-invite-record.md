# A remote knock keeps its stripped state in the invite record

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement `TestKnocking`, where knocking on a room on another server answered
`404 room not found`.

## Context and Problem Statement

`POST /knock/{roomIdOrAlias}` only knocked on rooms this server was in. Knocking on a room on
another server goes through `make_knock` and `send_knock`
([Knocking upon a room](../matrix-v1.19-spec/server-server-api.md#knocking-upon-a-room)), whose
response carries `knock_room_state`, "a list of state events to help the initiator of the knock
identify the room", translated to stripped state for clients; entries "which are improperly signed
or formatted SHOULD be removed". The knocking user's `/sync` shows it under `rooms.knock` as
`knock_state`. This server holds no state for a room it is not in, so that list has to be kept
somewhere. Before it is kept, each entry is checked as `send_join` state is: it must name the
knocked room and carry a valid signature from its sender's server.

v1.19 lists only `via` for `/knock`; `server_name` was the parameter before v1.12, and `/join`
here still accepts both.

## Decision Drivers

* The invite record (`invites`: the membership event that put the user there and the stripped
  state shown with it) is exactly what a knock needs, and DB-4 already ends it on join, leave or
  ban and replaces it when the knock is answered with an invite.
* No schema change for a record that already has the right shape and lifecycle.
* The owner decided the `server_name` question (2026-10-27).

## Considered Options

* Keep the knock's signed event and `knock_room_state` in the user's invite record, written by
  the `knock` membership projection.
* A separate `knocks` table with the same columns.
* Keep nothing, and show only the user's own membership as `knock_state`.

## Decision Outcome

Chosen option: the invite record. A `MembershipProjection` for `knock` may carry it, as one for
`invite` does; `/sync` builds `knock_state` from it when it exists and from the room's state when
the room is local. Every reader of the record looks it up only for a user whose membership is
`invite` (the `/sync` and sliding-sync invite sections) or deletes it, so a knock record is never
read as an invite. `POST /knock` takes its servers from `via` and `server_name`, like `/join`, and
routes them as a join does (ADR-0242).

### Positive Consequences

* The knocking user sees the room's name, topic and join rules, as the resident meant.
* The record ends with the knock, through the same transaction that changes the membership.

### Negative Consequences

* The table is named for invites. A reader added later that treats any row as an invite, without
  checking the user's membership, would show a knock as an invite.
