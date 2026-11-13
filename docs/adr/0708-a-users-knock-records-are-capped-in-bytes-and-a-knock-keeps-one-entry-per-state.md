# A user's knock records are capped in bytes, and a knock keeps one entry per state

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

ADR-0619 caps a user's knocks at 128 by count, and ADR-0620 bounds one knock's stored `knock_room_state` to 16 summary
entries of at most 64 KiB. Knocks had no per-user byte cap, and repeats of one (type, state_key) were not merged, so a
user running a federating server could store about 128 x 1 MiB of state their own server chose. Every `/sync` of that user,
incremental ones too, copied each record twice and parsed every stored entry under `runtime.mutex` (run-3 finding C31).

## Considered Options

* Cap the bytes of a user's knock records, keep one entry per state, and read the record by reference
* Cap the bytes only
* Store the knock's state already stripped, so `/sync` parses nothing
* Gate the knock rows of `/sync` on `since`

## Decision Outcome

Chosen option: "Cap the bytes of a user's knock records, keep one entry per state, and read the record by reference".

`invite_is_over_store_caps` charges a knock record against `max_remote_knock_bytes_per_user` (2 MiB, the knock event plus
its stored state, the record it replaces not counted twice), asked by the same writers and at the same points as the
count. `bounded_knock_room_state` keeps, for each (type, state_key), the last entry the resident sent, in the position of
the first, so a record holds at most seven summary entries and the user's own member event. The count limit of ADR-0620
still counts every entry that passed the type filter, before merging, so an over-long list is still dropped whole.
`build_invite_state_events_array` and `build_knock_state_events_array` read the record with `find_invite_row`, not the
copying `find_invite`.

Why the later entry wins: a state event later in the resident's list is the later state of that key; the first alone
would let a resident pin an old name.

Why not store the stripped form at knock time: it changes what the row holds, which the database and the invite path
share, and the cap already bounds the per-sync parse at 2 MiB. Left as a follow-up.

Why not gate on `since`: a knock's state can change only when the row is rewritten, but a client that lost its `since`
needs it, and the gate would not bound the initial sync.

Residual: a remote invite's state is still parsed on every `/sync` (bounded by ADR-0707's per-user 32 MiB and the 64 KiB
per invite), and a knock on a room this server holds reads `store.state` for the room.
