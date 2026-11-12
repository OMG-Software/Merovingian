# Remote invites are bounded in bytes per sending server and in all, not only per local user

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

ADR-0619 bounds what remote servers can make this server store for one local user (1024 invites, 32 MiB) and gives one
sending server an eighth of that per user. Across users one server was limited only by a count of 16384 invites, and the
server as a whole only by 32 MiB times the number of local users. An invite may carry 16 `invite_room_state` entries of up
to 64 KiB, so one remote server could keep about 16 GiB of invite records in memory and in the database, and the records
never expire (run-3 finding C04).

## Considered Options

* A byte ledger per sending server and in all, kept by the writers of `invites`, with a per-origin cap (64 MiB), a total
  cap (256 MiB) and a 64 KiB cap on one invite's `invite_room_state`
* Lower the per-user caps
* Expire invites
* Sum the origin's rows from `invite_origin_index` at each check

## Decision Outcome

Chosen option: "A byte ledger per sending server and in all", beside the three invite indexes. `append_invite_row`,
`replace_invite_row` and `erase_invite_row` keep it, `rebuild_invite_indexes` rebuilds it, and it is trusted only while
`invite_bytes_rows` equals `invites.size()`; a check that finds it out of step (rows just loaded, a test that edited the
vector) adds the rows up once instead, so a stale ledger costs time, never correctness. A check is two lookups.

The 64 KiB cap on the entries of one invite's `invite_room_state` is applied by `validate_invite_room_state` in every room
version, before any signature lookup, with 400 `M_INVALID_PARAM`. Stripped state is seven small events; a room version 12
set of full PDUs is a few kilobytes more, so 64 KiB leaves a wide margin.

Why not lower per-user caps: a legitimate user with many pending invites from many servers would be refused, and the
server-wide total still grows with the number of users.

Why not expiry: the spec states no expiry for a pending invite, and an invite a user is still deciding about would
vanish.

Why not summing from the origin index: it is cheap only up to the 16384 rows of one origin, and the server-wide total has
no index to sum.

Knocks are not charged here: they are created by this server's own users, not by a remote server, and stay bounded by
the 128 per user count.
