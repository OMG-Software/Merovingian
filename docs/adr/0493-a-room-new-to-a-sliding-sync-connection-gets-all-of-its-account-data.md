# A room new to a sliding sync connection gets all of its account data, whatever its age

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

The sliding sync `account_data` extension sent a room's account data only when a row's stream ID was greater than the
request's `since`. A room that entered the response for the first time on a connection (it moved into a list's window,
or was subscribed to) has been sent nothing, so its tags, `m.fully_read` and the rest, older than `since`, never reached
the client until they next changed.

MSC4186 is not part of Matrix v1.19, and v1.19 has no sliding sync. This reading relies on two things: the extension's
room account data is "for the rooms in the response", and a room the connection has not been sent (`initial: true`)
is described to the client in full, so what the client holds of it is empty. The same rule is what `/sync` applies to a room
the user has just joined (client-server-api.md, "Syncing": a joined room's `account_data` is "the private data that this
user has attached to this room"; the full state is sent for a room new to the client).

## Decision Outcome

`build_account_data` takes the set of rooms the connection is sent for the first time (`initial_room_ids`, the rooms the
handler builds with `is_initial`: not in `conn.rooms_seen`). Every room account data row of such a room is sent, whatever
its stream ID. Any other row goes down when its stream ID is greater than `since`, as before. Global account data is
unchanged.

* A room already sent is not sent its unchanged account data again, so a repeat poll costs nothing.
* The decision is made from the connection's own `rooms_seen`, not from `since`, which can come from another connection
  or a lost response.

## Consequences

Classic `/sync` has the same gap for a room the user newly joins in an incremental sync (`build_account_data_events`
filters on `since` alone). It is outside this decision and not changed here.
