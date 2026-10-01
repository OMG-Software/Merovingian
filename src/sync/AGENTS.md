# src/sync/ — Sync Module

Implements `/sync` (CS API v3), MSC4186 Simplified Sliding Sync (`/sync/v3` unstable),
sync filtering, stream tokens, and the sync notifier.

Spec authority:
- `/sync`: ../../docs/matrix-v1.19-spec/client-server-api.md#syncing
- Sliding sync: MSC4186 (unstable, `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`)

## Key files

| File | Responsibility |
|---|---|
| `stream_token.cpp` | Encode/decode stream ordering tokens; used for `since=` / `next_batch` / `from=` parameters |
| `sync_filter.cpp` | Parse and apply sync filter arguments (event type filters, room filters, timeline limits) |
| `sync_notifier.cpp` | Broadcasts new events to waiting long-poll sync requests; handles the `timeout=` wait |
| `sliding_sync_parser.cpp` | Parses MSC4186 request body (list operators, range, required_state, etc.) |
| `sliding_sync_room_list.cpp` | Builds the ordered room list for a sliding sync response |
| `sliding_sync_room_builder.cpp` | Constructs per-room response data (timeline, state, heroes) |
| `sliding_sync_extensions.cpp` | MSC4186 extensions (to_device, e2ee, account_data, typing, receipts) |
| `room_access.cpp` | `room_access_for()`: classifies a user's current membership of a room as joined / invited / none |
| `receipt_visibility.cpp` | `receipt_visible_to()`: the one rule deciding which viewers may see a stored receipt |
| `history_visibility.cpp` | `HistoryVisibility`: the one per-request filter deciding which room events a user may see (Room History Visibility rules, state at the event, fail closed) |
| `room_read_access.cpp` | `room_read_access_for()` / `room_state_event_ids()`: the one predicate deciding which room state a user may read (current, as of departure, or none) |
| `sliding_sync.hpp` (header-only) | Core sliding-sync connection-state, request and response types shared by the files above |
| `device_list_delta.cpp` | Device-list `changed` / `left` deltas for `/sync` and the e2ee extension |

## Stream token format

`next_batch` and `since` for `/sync` are opaque encoded triplets:
`<rooms_ordering>|<to_device_ordering>|<account_data_ordering>`

For `/messages` and timeline `prev_batch`, the token is a plain stream-ordering integer.
Use `stream_token.hpp` — never parse or construct tokens manually.

## Sliding sync connection state

MSC4186 tracks per-connection state keyed by `conn_id`. On a no-`pos` poll, the server
uses `conn.last_event_ordering` as the since-baseline so repeated `timeout=0` polls return
a delta (empty rooms, same pos) rather than re-sending the full initial sync.

## Sliding sync room access

A sliding sync request names rooms in `room_subscriptions` and in the `receipts`/`typing`
`rooms` arrays. None of those names is proof of entitlement: a user needs to join a room to
view events in it (C-S API, "Room history visibility"). Classify every client-named room with
`room_access_for()` before reading anything about it:

- `joined`: serve in full.
- `invited`: stripped invite state only (`invite_state`), no timeline, no `required_state`.
- `none` (no membership, leave, ban, knock): omit silently.

`world_readable` is not permission to subscribe. The extensions drop rooms the caller has not
joined. `parse_sliding_sync_request` clamps `timeline_limit` to
`sliding_sync_max_timeline_limit`; `sliding_sync_request_limit_violation` caps subscriptions
and `required_state` pairs (the handler answers a violation 400 `M_INVALID_PARAM`). Every new
extension that takes a client-named room list must gate on `room_access_for()` too.

## Receipt visibility

`/sync` and the sliding sync receipts extension decide what a viewer may see of a stored
receipt through `receipt_visible_to()` and nothing else: `m.read` is public, `m.read.private`
is visible only to the user who sent it, `m.fully_read` never appears in `m.receipt` (it is
the owner's room account data), and an unknown type is withheld. Do not index
`rt.receipts` by type without going through it.

## History visibility and room read access

**Every client read path that returns room events or room state goes through these two, and
nothing else decides what a user may see** (ADR-0084; audit CSAZ-2, CSAZ-3).

- `HistoryVisibility{store, user}` (`history_visibility.hpp`) answers "may this user see this
  event?" by the spec's five rules against the state recorded for the event (its ADR-0064 state
  group), with the two before-or-after special cases (`m.room.history_visibility` events and
  the user's own `m.room.member` events). Build **one per request** and reuse it across rooms
  and events: it caches per state group and builds its indexes over the store lazily, once.
  Call `can_see()` on every event a response would carry: timelines (`/sync`, sliding sync),
  `/messages`, `/context` (target and both lists), `/event`, `/search` and its per-result
  context, `/relations`, `/threads`, the `initialSync` chunk. A new endpoint that returns room
  events must call it.
- It fails closed. A broken group chain, a group naming an event the store lacks, or a
  rejected or soft-failed event means not visible. Never substitute the room's current state.
  An event with no state group (pre-ADR-0064 history) is judged by rule 2 alone from the user's
  own membership timeline; an undeterminable timeline denies.
- `room_read_access_for(store, room, user)` (`room_read_access.hpp`) answers "what room state
  may this user read?": `current` (joined), `as_of` (was joined and left, was kicked or banned:
  the state recorded at the event that ended the join, `boundary_event_id`), or `none` (knock,
  invite, declined invite, never joined, forgotten). `room_state_event_ids()` returns the state
  for it, optionally at an `at` position, never later than the boundary. It gates `initialSync`,
  `/members`, `/joined_members` (current only), `/state` and `/state/{type}/{key}`.
- A user with no read access may still peek events (not `/members` or `/state`) when the
  room's **current** visibility is `world_readable` (`room_is_world_readable`); each event is
  still judged on its own state.
- `/messages` moves its token past hidden events and examines at most
  `ClientApiLimits::max_messages_events_examined` events per page.

Tests that write events straight into a `PersistentStore` must record a state group for them
(`tests/support/room_history_fixture.hpp`), or the filter hides them.

## Device lists

`changed` and `left` name *users*, not change events: a user appears at most
once across both lists however many rows the store holds for it in the range —
spec: client-server-api.md, "Extensions to /sync".

An initial sync (`since` absent, or a sliding sync with no `pos`) deliberately
reports the full set rather than nothing, so a freshly logged-in device is
prompted to `/keys/query` its own user's devices straight away. The spec permits
either ("the server need only populate this property for an incremental
`/sync`"); this project chose to populate, and
`tests/unit/test_sync_handler.cpp` pins that behaviour. Deduplication is what
keeps the initial response bounded.

All three surfaces that report device-list changes — `/sync`, the MSC4186 e2ee
extension, and `GET /_matrix/client/v3/keys/changes` — go through
`collect_device_list_delta` (`sync/device_list_delta.hpp`). It collapses the
store's append-only change log to one entry per subject user, so a subject is
never repeated however many rows the range covers, and resolves a subject that
both changed and left to whichever came last. Do not walk
`store.device_list_changes` directly.

## Long-poll behaviour

`sync_notifier` holds requests until an event arrives or `timeout` expires.
- On the `sync_pool` path the wait is polled in 1-second slices (`http_server.cpp`), which bounds
  shutdown and dropped-client detection to one second; the no-pool fallback and the sliding-sync
  re-wait loop wait for the full remaining timeout in a single call
- The sync thread pool (`sync_pool`) is separate from the main thread pool to prevent
  long-polling clients from starving federation and other short-lived requests

## Key spec sections

- [Syncing](../../docs/matrix-v1.19-spec/client-server-api.md#syncing)
- [Filtering](../../docs/matrix-v1.19-spec/client-server-api.md#filtering)
- [MSC4186 Simplified Sliding Sync](../../docs/matrix-v1.19-spec/client-server-api.md)
