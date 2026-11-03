# Bound account-data rows and the tags of a room

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-12, the m.tag row of a room grew past any request body

## Context and Problem Statement

`PUT /user/{userId}/rooms/{roomId}/tags/{tag}` reads the room's whole `m.tag` row, adds one member and writes it back
through `set_account_data`, which applies no limit (ADR-0197 lets server-written rows through the type cap). A user
could repeat it with new tag names and 1 MiB values until the row was gigabytes, and every later tag request and
`/sync` parsed it whole under `runtime.mutex`. The spec says only "The name of a tag MUST NOT exceed 255 bytes"
(client-server API, "Room Tagging"); it states no count or size.

## Considered Options

* A byte limit in the account-data store layer, plus a tag count and tag size in the handler
* A limit in the tags handler only
* Count `m.tag` as a type against ADR-0197's per-room cap

## Decision Outcome

Chosen option: "A byte limit in the store layer, plus a tag count and size in the handler".

* `database::max_account_data_row_bytes` (262144) bounds the content of any account-data row. `store_account_data`
  refuses a larger row (so the rows the server writes itself are bounded), and the two capped writers return
  `CappedAccountDataStore::too_large`, which the account-data `PUT` answers with `400 M_TOO_LARGE`. A client's `PUT`
  was bounded by the body only (1 MiB, replaced not accumulated); it now shares this limit.
* A tag name over 255 bytes is `400 M_INVALID_PARAM`. A user holds at most `max_tags_per_room` (100) tags on a room and
  each tag's JSON value is at most `max_tag_value_bytes` (1024); over either is `400 M_TOO_LARGE` and nothing is stored.
  Changing a tag the user already has never counts against the number.

The limit on tag count and value size is a handler constant, not configuration. A handler-only limit was rejected
because `m.tag` is not the only row the server grows by read-modify-write, and the generic account-data `PUT` shares
the store limit. Counting `m.tag` against the type cap was rejected: ADR-0197 deliberately never refuses the row.

### Negative Consequences

* An `m.direct` or other account-data row over 256 KiB, which the account-data `PUT` accepted up to 1 MiB, is now
  refused. Element's rows are a few KiB.

## Links

* Extends [ADR-0197](0197-room-account-data-needs-a-membership-and-is-capped-per-room.md)
