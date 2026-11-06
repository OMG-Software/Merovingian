# A room new to a sliding sync connection gets all of its account data, whatever its age

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

The sliding sync `account_data` extension sent a room's account data only when a row's stream ID was greater than the
request's `since`. A room that entered the response for the first time on a connection (it moved into a list's window,
or was subscribed to) has been sent nothing, so its tags, `m.fully_read` and the rest, older than `since`, never reached
the client until they next changed.

**No text states the rule.** Matrix v1.19 has no sliding sync. MSC4186 (`erikj/sss` branch,
`proposals/4186-simplified-sliding-sync.md`) says under "Extensions" only that extensions "will be specified in future
MSCs", naming account data as a future example; it defines no account-data extension, and so nothing about the age of a
room's rows. The rule below is this server's own reading, chosen because the alternative leaves a client without data it
has never been given. It is not MSC4186's.

For the nearest text in v1.19, classic `GET /sync` (client-server-api.md line 11628, `JoinedRoom.account_data`) says only
"The private data that this user has attached to this room." It does not say whether a room first appearing in an
incremental sync carries all of its account data or only what changed. `state` in the same table does say "all state up to
the start of the timeline, if `since` is not given, or `full_state` is true", and a newly joined room is sent in full by
this server's state path; the account data of such a room is not.

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
filters on `since` alone). The spec text above does not decide it either way, so it is not changed here.
