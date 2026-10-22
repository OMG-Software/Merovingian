# Room account data needs a membership in the room and is capped per room

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, R10 (room-scoped account data `GET`/`PUT` absent)

## Context and Problem Statement

`PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}` lets a client store
any event type against any room ID. ADR-0173 capped global account data and left room account
data uncounted because, until now, only the tags API (which requires a join) and read markers
wrote it, so membership bounded it. With the generic endpoint, one user could add rows without
bound by inventing room IDs or types, and every `/sync`, sliding-sync `account_data` extension and
account-data read scans those rows while holding `runtime.mutex`.

The spec lists no membership requirement and no limit for this endpoint. Its responses are 200,
400 (`M_NOT_JSON`/`M_BAD_JSON`, or `M_INVALID_PARAM` for a malformed room ID), 403 and 405.

## Decision Drivers

* Work done under `runtime.mutex` must not grow with input one client controls (security audit
  run-1).
* Account data for a room the user has left is still meaningful: `/sync` delivers it in the
  `leave` section, so writing it after leaving must keep working.
* Caps refuse rather than evict and are operator-configurable (ADR-0118, ADR-0173).

## Considered Options

* Require a membership row of any kind in the room, and cap the client-set types per (user, room)
* Require a current join, as the tags API does, and cap per (user, room)
* No membership requirement; cap the user's room rows in total
* Count room rows against the ADR-0173 global cap

## Decision Outcome

Chosen option: "require a membership row of any kind, and cap per (user, room)".

A `PUT` is refused with `404 M_NOT_FOUND` ("room not found") unless the store holds a
`memberships` row for the user in that room, whatever its value (join, invite, knock, leave, ban).
A room the user has forgotten has no row and is refused. The 404 is the answer the tags API
already gives here for a room the user may not use, and it does not reveal whether the room
exists. `GET` has no membership requirement: it reads only the caller's own rows.

A new type past `server.client_api.max_room_account_data_per_room` (default 100, 1 to 100000,
restart to change) in that room is refused with `400 M_TOO_LARGE`; an update to a type the user
already holds there always succeeds. `database::store_room_account_data_within_cap` counts the
types and finds the row in one pass, as the global form does. The `m.tag` and `m.fully_read` rows
written by the tags and read-marker APIs go through `set_account_data`: they count towards the cap
but are never refused.

Rows are therefore bounded by (rooms the user has a membership in) × (per-room cap). Each of those
rooms cost a membership event that the server stored.

### Positive Consequences

* One user can no longer grow the rows that account-data reads scan, by room or by type.
* A left room keeps working, matching what `/sync` delivers for it.

### Negative Consequences

* A client writing more than 100 distinct types to one room is refused until an operator raises
  the cap. Element writes fewer than 10.
* A `PUT` for a room the user never had a membership in answers 404, a status the spec does not
  list for this endpoint.

## Pros and Cons of the Options

### Require a current join

* Good, because it matches the tags API.
* Bad, because a user who left a room could not update account data that `/sync` still delivers
  for it.

### Cap the user's room rows in total

* Good, because it needs no membership lookup.
* Bad, because a user in many rooms would hit it through ordinary tagging and read markers, the
  reason ADR-0173 kept room rows out of its cap.
* Bad, because without a membership check the rows can be spread over invented room IDs.

### Count room rows against the global cap

* Bad, for the same reason ADR-0173 rejected it: tagging many rooms would exhaust it.

## Links

* Refines [ADR-0173](0173-cap-global-account-data-types-per-user.md): room account data is no
  longer bounded by membership alone
* Follows [ADR-0118](0118-refuse-e2ee-and-filter-uploads-at-per-user-caps.md)
