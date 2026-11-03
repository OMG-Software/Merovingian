# A left room's /sync state is gated by room read access

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-41. Refines [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md).

## Context and Problem Statement

ADR-0084 names `sync::room_read_access_for` as the predicate for every read of room state. The
`rooms.leave` section of an initial classic `/sync` (`build_left_room`) did not use it. It built
`state` from the state before the first timeline event, or from the leave event's own state group,
and exempted the user's own leave or ban from `HistoryVisibility`. For a user with `RoomReadKind::none`
(a retracted knock, a declined invite, a ban before any join) that leave anchored a read of the
room's whole state: roster, power levels, settings, custom state. `GET /state` and `/members`
refused the same user with 403.

## Decision Outcome

`sync_json` computes `room_read_access_for` for each left room and passes it to `build_left_room`.

* `none`: `state` holds no room state. The user's own leave or ban is the one event that is
  reported, in the timeline, or in `state` when the timeline filter excludes it (the rule an
  incremental sync already followed). An initial sync and an incremental sync now agree.
* `as_of`: the state is the state the existing code builds (before the first timeline event, or the
  leave's own group) while the event it is anchored on is at or before the access boundary. When the
  anchor is later (a user who left and was then banned, or a timeline event received after the
  leave), the state is `room_state_event_ids` at the boundary, never later.
* An ordinary user who joined and left keeps exactly the state they were given.

Rejected: building every `as_of` state with `room_state_event_ids` at the first event's ordering.
That is the state after the preceding event in stream order, which is not always the state before
the event in the room's graph (backfilled events), so it would change what ordinary users receive.
The cap is applied only where the anchor can exceed the boundary.

Sliding sync is not affected: it omits a room the user has left or been banned from
(`room_access_for` is `none`, `src/sync/AGENTS.md` "Sliding sync room access"), and it has no
`include_leave`.
