# src/sync/ — Sync Module

Implements `/sync` (CS API v3), MSC4186 Simplified Sliding Sync (`/sync/v3` unstable),
sync filtering, stream tokens, and the sync notifier.

Spec authority:
- `/sync`: ../../docs/matrix-v1.19-spec/client-server-api.md#syncing
- Sliding sync: MSC4186 (unstable, `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`)

## Key files

| File | Responsibility |
|---|---|
| `StreamToken.cpp` | Encode/decode stream ordering tokens; used for `since=` / `next_batch` / `from=` parameters |
| `ToDevicePosition.cpp` | Encode/decode the sliding sync `to_device` extension's position with its stream token epoch; exact decimal parse (ADR-0592) |
| `SyncFilter.cpp` | Parse and apply sync filter arguments (event type filters, room filters, timeline limits); `PreparedRoomEventFilter`, the same rules over hash sets and a sorted prefix list for a caller that judges many events (`POST /search`, ADR-0332). A change to the rules in `event_passes_filter` / `room_passes_filter` goes into both; `test_prepared_room_event_filter.cpp` holds them equal |
| `TypePattern.cpp` | `type_pattern_matches`: the `*` wildcard (anywhere, any number of times) of `types` / `not_types`, iterative with no backtracking (ADR-0541); the one matcher both filter paths use |
| `SyncNotifier.cpp` | Broadcasts new events to waiting long-poll sync requests; handles the `timeout=` wait |
| `ParkedPollRegistry.cpp` | `ParkedPollRegistry`: parked long-polls (an opaque `ParkedPoll` each) indexed by user and by deadline, one thread that resumes woken and expired ones through a callback; mutex is a leaf; owned by `SyncNotifier` (ADR-0569) |
| `TimelineWindow.cpp` | `newest_timeline_window`: a classic `/sync` room's timeline, read newest first through the room index, stopping when full and after `max_timeline_rows_skipped` rows not taken (ADR-0616) |
| `SlidingSyncParser.cpp` | Parses MSC4186 request body (list operators, range, required_state, etc.) |
| `SlidingSyncRequestLookups.cpp` | `SlidingSyncRequestLookups`: one per sliding sync request, learns the caller's joined rooms and invites (own membership rows), encryption and room type (state index), `m.direct`, favourites and read markers (one receipt pass), and the `by_recency`/`by_name` keys per room (ADR-0666), each once; every list and `build_room_response` reads it (ADR-0665) |
| `SlidingSyncRoomList.cpp` | Builds the ordered room list for a sliding sync response |
| `SlidingSyncRoomBuilder.cpp` | Constructs per-room response data (timeline, state, heroes) |
| `SlidingSyncExtensions.cpp` | MSC4186 extensions (to_device, e2ee, account_data, typing, receipts) |
| `RoomAccess.cpp` | `room_access_for()`: classifies a user's current membership of a room as joined / invited / none; `room_access_index()`: the same answer for all of a user's rooms in one pass |
| `ReceiptVisibility.cpp` | `receipt_visible_to()`: the one rule deciding which viewers may see a stored receipt |
| `ReceiptContentBuilder.cpp` | `ReceiptContentBuilder`: the one builder of an `m.receipt` event's content (with `thread_id`), shared by `/sync` and sliding sync |
| `BundledAggregations.cpp` | `BundledAggregations`: the one builder of `unsigned.m.relations` (`m.replace`, `m.thread`, `m.reference`) for an event served to a client (ADR-0430) |
| `ViewerEventUnsigned.cpp` | `ViewerEventUnsigned`: adds the requesting user's `unsigned.membership` and, for the sending device, `unsigned.transaction_id` to a client event |
| `ReadMarkers.cpp` | `ReadMarkers`, `read_markers_for()`, `event_thread_id()`: where a user has read up to, unthreaded and per thread |
| `HistoryVisibility.cpp` | `HistoryVisibility`: the one per-request filter deciding which room events a user may see (Room History Visibility rules, state at the event, fail closed) |
| `RoomReadAccess.cpp` | `room_read_access_for()` / `room_state_event_ids()`: the one predicate deciding which room state a user may read (current, as of departure, or none) |
| `SlidingSync.hpp` (header-only) | Core sliding-sync connection-state, request and response types shared by the files above |
| `DeviceListDelta.cpp` | Device-list `changed` / `left` deltas for `/sync` and the e2ee extension |

## Stream token format

`next_batch` and `since` for `/sync` (and sliding sync `pos`) are `StreamToken`s: lowercase hex components
`<event_ordering>_<membership_ordering>_<sync_stream_id>` and, when the database has one (always, in production),
`_<epoch>`. The epoch is the database's stream token epoch (ADR-0592): a random value drawn at first start and
replaced by `merovingian-server --after-restore`. A token whose epoch is not the store's (`stream_token_epoch`),
including one with no epoch, is foreign whatever its positions: `/sync` serves it as an initial sync, sliding sync
answers `400 M_UNKNOWN_POS`, `/keys/changes` reads it as the start (`from`) or the current position (`to`). The
sliding sync `to_device` extension's `since`/`next_batch` is a `ToDevicePosition` (`<decimal stream id>_<decimal
epoch>`, `ToDevicePosition.hpp`), and one from another epoch acknowledges nothing. Any token that lets the
server delete or skip something carries the epoch and is compared with the store's before it is trusted; a
pagination token (`/messages`, `/relations`, `prev_batch`), which only names where to read from, does not.

For `/messages` and timeline `prev_batch`, the token is a plain stream-ordering integer.
Use `StreamToken.hpp` — never parse or construct tokens manually.

A token is unauthenticated client input: decoding it proves nothing about who issued it. It never moves
server-wide state. A classic `/sync` token ahead of any stream is served as an initial sync; a sliding sync
`pos` ahead of one gets `400 M_UNKNOWN_POS`. `allocate_sync_stream_id` is the only thing that raises the
counter, and it throws rather than pass `INT64_MAX`. Event, room and membership writes stop
`sync_stream_write_reserve` below that, so code that stores one and then allocates never reaches the throw with it
committed. Other writes followed by a position check `sync_stream_has_write_reserve` first, unless they revoke access
(ADR-0315).

## Joined-room timelines and holes in the event graph (ADR-0289)

A classic `/sync` joined room's `timeline` is the newest `timeline_cap` events after `since` that pass
the filters, read by `newest_timeline_window` from the newest row (ADR-0616). `limited` is true when that window was cut by
the cap, when the walk ran out of its budget of rows not taken, **or** when an event in it has a hole
before it: any ID in its `prev_events` that is not *held*, i.e. has no `store.events` row or a row whose
status is `outlier` with no state group (rejected and soft-failed rows are held; an outlier that `/get_missing_events` or backfill placed has a state group and is held, ADR-0290). The window then starts at the newest such
event (kept: the hole lies before it) and `prev_batch` is that event's stream ordering, so `/messages`
(and its backfill) reaches what lies before. An outlier is never the event the check starts from. Select the room's events through
`store.events.room_in_stream_order(room_id)` (ADR-0435: the room's own rows, every status, already in stream order),
never a walk of `store.events` filtered by room. Look
only at the window's events and look prev events up with `EventTable::contains`/`find` (indexed); never
scan the store per event, this runs under `runtime.mutex`. A limited incremental response also carries
the state at the start of the timeline. Sliding sync has its own builder and `limited` rule and is not
affected.

## Sliding sync connection state

MSC4186 tracks per-connection state keyed by `conn_id`. On a no-`pos` poll, the server
uses `conn.last_event_ordering` as the since-baseline so repeated `timeout=0` polls return
a delta (empty rooms, same pos) rather than re-sending the full initial sync.

The connections are a `SlidingSyncConnectionTable` (map plus an index by `last_used`): change them only through `touch`, `erase` and `erase_idle`, so the idle sweep pops from the index front and never walks every user's connections (ADR-0663).

## Sliding sync timelines

A room's `timeline` is the newest `timeline_limit` events the user may see, after its delta
floor unless the room is initial or expanded. Whenever it holds fewer events than it could,
`build_room_response` sets `limited`. Every non-empty timeline gets `prev_batch`, the stream
ordering of its oldest event, because `/messages?dir=b` returns events strictly older than
`from`. Never truncate a timeline without both: a client takes an unflagged timeline for the
room's whole history (Element X's room list asks for `timeline_limit: 1`; 0.12.45).

When a request raises a seen room's effective `timeline_limit` past
`room_timeline_limits[room]` (`timeline_limit_expands`), the room is built with
`TimelineExpansion::expand`: the latest events are resent and `expanded_timeline` is set if any
predates the last send. `required_state` keeps its floor. The handler skips the long-poll for such
a request, but only once per request `pos` (`expansions_answered`, ADR-0221). A pos no stream
advanced is not acknowledged by a repeat, so skipping again would spin the client. Record the
effective limit of every room built, or the next request expands it again.

Which list rooms can expand is read from each list's previous window while its config is
unchanged (`list_configs`). A list that is new or changed is computed before the long-poll
decision, because its window can hold a sent room its previous window lacked. Lists are not
sticky (MSC4186), so a response keeps only its own request's lists in `list_configs` and
`list_prev_windows`; a list dropped and sent again is new. Do not compute
every list before that decision: ranking the room list walks the unread counts under
`runtime.mutex`, and an idle long-poll is woken by every unrelated stream bump.

## Sliding sync room access

A sliding sync request names rooms in `room_subscriptions` and in the `receipts`/`typing`
`rooms` arrays. None of those names is proof of entitlement: a user needs to join a room to
view events in it (C-S API, "Room history visibility"). Classify every client-named room before
reading anything about it: `room_access_for()` for a single room, `room_access_index()` for a
request that names many:

- `joined`: serve in full.
- `invited`: stripped invite state only (`invite_state`), no timeline, no `required_state`.
- `none` (no membership, leave, ban, knock): omit silently.

`world_readable` is not permission to subscribe. The extensions drop rooms the caller has not
joined. `parse_sliding_sync_request` clamps `timeline_limit` to
`sliding_sync_max_timeline_limit`; `sliding_sync_request_limit_violation` caps subscriptions,
`required_state` pairs, lists (32), sort keys per list (3) and `bump_event_types` per list (64)
(the handler answers a violation 400 `M_INVALID_PARAM`). It also caps `room_types`/`not_room_types` (16 each), ranges (16) per list, a `conn_id` and list name (255 bytes) and the bytes of lists a request would make a connection keep (64 KiB; `sliding_sync_retained_bytes`); `sliding_sync_json` refuses a request that would take the device's connections past 256 KiB together, before creating its entry (ADR-0663). A new field a connection stores copies into `sliding_sync_retained_bytes`.

A room's sliding sync timeline is read through `newest_timeline_window`, like `/sync`'s, so it stops after `max_timeline_rows_skipped` rows not taken and then is `limited` with a `prev_batch` where the walk stopped (ADR-0664). Never add a loop over `room_in_stream_order` that `continue`s on a visibility test.

A list filter or sort key reads the request's `SlidingSyncRequestLookups`, never a scan of `store.memberships`, `store.state` or `store.receipts` per room (ADR-0665); a new filter adds a lookup there.

`compute_room_list` sorts while the runtime lock is held. Every sort key is computed once per
room before `std::stable_sort`, never inside the comparator, which runs O(N log N) times
(ADR-0172). Every new
extension that takes a client-named room list must gate on room access too.

When a request names many rooms, classify them through `room_access_index()`, built once per
request, not `room_access_for()` per room: each `room_access_for()` call scans every membership
row in the store, and this runs under the runtime lock. `build_extensions` builds one index for
receipts and typing; the sliding-sync handler in `ClientServerRuntime.cpp` builds one for
`room_subscriptions` and passes it to `build_extensions`, so a request scans the memberships once. The
receipts and typing `rooms` arrays are de-duplicated by the parser and capped at
`room_subscriptions` (ADR-0174). A new client-named room list gets the same cap.

## Sliding sync account data

The `account_data` extension sends a global row when it changed after `since`, and a room row when it changed after `since`
or when the room is new to the connection (`initial_room_ids`: built with `is_initial`, so not in `conn.rooms_seen`): such a
room has been sent nothing, so all of its room account data goes down (ADR-0493). Neither v1.19 nor MSC4186 states this rule; it is this server's reading, set out in
that ADR. A room in the response is found through a hash set of `response_room_ids`, never a scan per row.

A room's timeline is built newest first and stops at `timeline_limit + 1` events (ADR-0494); a filter added to that walk is a
per-event test. Counts, heroes and required state read the room's own membership and state rows
(`for_each_room_membership_row`, `for_each_room_state_row`, `find_current_state_event_id`), never `store.memberships` or
`store.state` filtered by room.

## Receipt visibility

`/sync` and the sliding sync receipts extension decide what a viewer may see of a stored
receipt through `receipt_visible_to()` and nothing else: `m.read` is public, `m.read.private`
is visible only to the user who sent it, `m.fully_read` never appears in `m.receipt` (it is
the owner's room account data), and an unknown type is withheld. Do not index
`database.persistent_store.receipts` by type without going through it.

Receipts are durable rows (`database::store_receipt`, ADR-0169), keyed by
`(room, type, user, thread_id)`. Build `m.receipt` content with
`ReceiptContentBuilder`, which carries `thread_id`. `/sync` emits
`build_per_thread()`: one `m.receipt` event per categorisation (unthreaded, `main`, each
thread root), because one event's content holds a single receipt per user, type and event
and an unthreaded and a threaded `m.read` for one event are two receipts (Receipts, "one
event per room and thread"). `build()` merges them, keeping the latest, for sliding sync,
whose receipts extension carries one event per room.

## Left rooms in `/sync`

`rooms.leave` lists rooms the user left or was banned from (`membership` `leave` or `ban`).
`build_left_room` (`ClientServerRuntime.cpp`) builds each: the room's events after `since` up to the
event that ended the stay, selected by the request's timeline filter (`types`, `senders`,
`contains_url`; `limit` 0 means none, `EventTypeFilter::limit_given`) and by
`HistoryVisibility`, the newest `limit`, with `limited` and `prev_batch`. The user's own leave or
ban is shown whatever the visibility says, so a rejected invite under `joined` visibility still
reports it. Initial-sync `state` is the state at the start of the timeline, or as of the leave
when the timeline is empty; an incremental sync's `state` carries the leave only when the
timeline does not. An incremental sync lists a leave once, after `since`; `include_leave` lists
left rooms on an initial sync only. `sync_json` computes `room_read_access_for` per left room and
`build_left_room` obeys it (ADR-0357): `none` (a retracted knock, a declined invite, a ban before
any join) gets no room state, only the user's own leave or ban, in the timeline or, when the
timeline filter excludes it, in `state`; `as_of` never gets state later than the access boundary
(a user who left and was then banned). Never build a left room's state without that access. A forgotten room has no membership row and is never listed
(Leaving rooms: "forgotten ... will never appear in the response to `/sync`"). Do not add the
events after the leave to a left room's timeline.

## Viewer-dependent `unsigned`

A client's `unsigned` is never the stored one, filtered: `unsigned` is outside every signature, so a remote
sender can put anything in it (`m.relations`, `redacted_because`, `prev_content`, `age`, `transaction_id`,
`membership`). `client_event_with_id` and sliding sync's `client_event_json` drop it and build it from what the
server computes: `replaces_state`, `redacted_because` and the viewer's values below (ADR-0402). A new client-event
serializer does the same; a new `unsigned` field is added to what the server computes, never passed through.
Sliding sync applies `ViewerEventUnsigned` too (`build_room_response` takes the request's `device_id`).

`unsigned.membership` and `unsigned.transaction_id` depend on who asks, so they are added per
request by `ViewerEventUnsigned`, never stored. `transaction_id` is given only to the device
that sent the event (`client_txn_ids.device_id`; a transaction ID is scoped to a device, and a
login that names an existing `device_id`, or a token refresh, is the same device). It reads the
record through `database::find_client_txn_by_event_id`, one hash lookup per event served; never
scan `client_txn_ids` per request, the table grows with every message the server stores and
nothing prunes it. `membership`
comes from `HistoryVisibility::membership_at`: the user's `m.room.member` state in the state group
after the event, `leave` before they had any. `/sync` timelines and `GET .../event/{eventId}`
use it; a new read path that returns timeline events to a client should too.

## Bundled aggregations (ADR-0430)

`unsigned.m.relations` is built by `BundledAggregations` and nothing else, at the point an event is serialized:
`/messages`, `/context`, `/event`, the `/relations` forms, `/search` (results and context), `/threads`, `/sync`
and sliding sync. `/sync` and sliding sync pass `enabled = limited` (spec: only a `limited` section); a new
read path that returns timeline events calls `make_bundled_aggregations` (`RoomService.hpp`) and `apply()`.
Children come from `EventTable::for_each_relation_child_newest_first`, never a scan of `store.events`, capped
by `max_aggregated_children_examined` (per relation kind, so one kind never exhausts another's window), `max_aggregated_edits_parsed` and `max_reference_chunk_entries`. A child
counts only if it is in the parent's room, not rejected or soft-failed, not from an ignored sender and
`HistoryVisibility::can_see`. A stored `unsigned.m.relations` is never passed through. State events get none, a
redacted original gets no `m.replace`, and `latest_event` is the greatest `(depth, stream_ordering)`
(`is_later_in_thread`, shared with `/threads`).

## Unread counts

Every unread count `/sync` and sliding sync report (`unread_notifications`, sliding
sync's counts, the `by_notification_count` sort) is computed from
`read_receipt_markers()` with `count_notifications()` / `count_highlights()`;
`GET /notifications` `read` asks the same markers (`ReadMarkers::covers()`). The
push badge has a pass of its own (below). Spec: "the server is to partition the
notification count to each thread". An unthreaded receipt covers every earlier
event; a threaded one covers only its own thread (`main` or the root), found by
`event_thread_id()` through up to 3 relation hops.
Do not compare an event's stream ordering with a single receipt position: that
is the bug a threaded receipt used to cause. A non-state event the user sent also
reads its own thread (`read_markers_for`, ADR-0170); never let a state event do
so, or a profile change would mark every room read.

`read_markers_for()` finds each receipt's event with `find_in_room` and reads the user's own events through
`room_in_stream_order`; `count_unread_by_thread()` walks that room index too, both newest first and for at most
`max_unread_rows_examined` (1000) rows (ADR-0435, ADR-0617). `count_unread_by_thread()` is the one walk for these counts; `/sync` reports its
split when the filter sets `unread_thread_notifications`. What counts is the
user's push rules' decision (R15, ADR-0205): the walk asks a
`sync::UnreadEventClassifier` (`homeserver::PushRuleUnreadClassifier` in
production) about every unread event, and counts only events after
`counted_after()`, the start of the user's current join. Never decide notify or
highlight from the event type or `m.mentions` here. Only `accepted` events the
user may see count: the walk asks `unread.visible()` (`HistoryVisibility::can_see`,
the request's own filter for `/sync` and sliding sync) before it classifies,
because a backfilled event from before the join is ordered after it. `visible()` is also
false for a non-state event from a sender the user has ignored (Ignoring Users: the client
no longer receives it; state events still count). The classifier resolves the user's
`m.ignored_user_list` once, at construction (`trust_safety::resolve_ignored_users`), and
`visible()` parses an event's JSON only when its sender is ignored, so this adds no per-event
scan; /sync, sliding sync and the push badge all get it through the classifier.

Build one classifier per request and pass it to every count in that request
(`/sync`, `compute_room_list`, `build_room_response`). It loads the user's rules
once, and on first use gathers every room's facts from one walk each of the
memberships and the current state (event lookups through the request's
`HistoryVisibility` index). A room's join start comes from the user's member events,
walked back through their recorded predecessors (ADR-0617). Never add a lookup to it
that walks a whole table per room (ADR-0207).

The push badge (`homeserver::count_push_badge`, the Push Gateway `counts.unread`)
does not use `count_unread_by_thread()`: it runs under `runtime.mutex` for every
recipient of every event, so it makes one walk of the events, newest first in
stream order (`in_stream_order()`, ADR-0215), stops once every room is settled,
visits at most 10000 rows and saturates at 1000 (ADR-0207). It applies the same
rules through shared helpers (`member_transition`, `join_start_from`,
`event_thread_id`, the classifier) and resolves receipt positions as
`read_markers_for()` does; tests hold it equal to the walk whenever it is not
capped. Change one, change both. Capped, it is a lower bound that never counts an
event `/sync` would not. Its setup walks each table a fixed number of times
(`PushBadgeCount::table_walks`), whatever the number of rooms. `/sync` and
sliding sync are exact up to `max_unread_rows_examined` rows and a lower bound past it (ADR-0617).

## History visibility and room read access

**Every client read path that returns room events or room state goes through these two, and
nothing else decides what a user may see** (ADR-0084; audit CSAZ-2, CSAZ-3).

- `HistoryVisibility{store, user}` (`HistoryVisibility.hpp`) answers "may this user see this
  event?" by the spec's five rules against the state recorded for the event (its ADR-0064 state
  group), with the two before-or-after special cases (`m.room.history_visibility` events and
  the user's own `m.room.member` events). Build **one per request** and reuse it across rooms
  and events: it caches per state group and builds its indexes over the store lazily, once.
  Call `can_see()` on every event a response would carry: timelines (`/sync`, sliding sync),
  `/messages`, `/context` (target and both lists), `/event`, `/search` and its per-result
  context, `/relations`, `/threads`, the `initialSync` chunk. A new endpoint that returns room
  events must call it.
- Rule 3 (`shared`: the user joined "after the event was sent") compares the depth of the user's newest
  accepted join with the event's depth, never stream orderings (ADR-0308): an event fetched as history is
  stored after the join it precedes. Do not order by stream ordering anywhere the question is "before or after
  in the room". Depth is chosen by whoever creates an event (a federated join's by the resident), so for a user
  whose membership is `leave` or `ban` an event the depth rule allows is hidden if it descends from their leave
  (`may_descend_from_departure`, ADR-0311): a walk of held `prev_events` that stops at events stored before the
  leave and at events not held, and fails closed past 500 events or when the leave event is not held. Never
  replace it with a local depth: after a federated join the join's predecessors are not held (ADR-0311).
- It fails closed. A broken group chain, a group naming an event the store lacks, or a
  rejected or soft-failed event means not visible. Never substitute the room's current state.
  An event with no state group that is not an outlier (pre-ADR-0064 history, stored `accepted`) is judged by rule 2
  alone from the user's own membership timeline; an undeterminable timeline denies.
  An outlier with no state group was fetched as history (ADR-0069, ADR-0070): its place in the room is unknown and
  its stream ordering is the fetch time, so it is denied (ADR-0415) until a snapshot gives it a state group, when
  the ordinary check applies. Do not judge a group-less outlier by rule 2.
  The one exception is the user's own `m.room.member` event held as an outlier with no state group
  (a received invite, the leave that rejected it): it is visible to that user, who was sent it already
  (ADR-0304). Do not widen it to other events or other users.
- `room_read_access_for(store, room, user)` (`RoomReadAccess.hpp`) answers "what room state
  may this user read?": `current` (joined), `as_of` (was joined and left, was kicked or banned:
  the state recorded at the event that ended the join, `boundary_event_id`), or `none` (knock,
  invite, declined invite, never joined, forgotten). `room_state_event_ids()` returns the state
  for it, optionally at an `at` position, never later than the boundary. The state at a position is the state
  recorded for `state_anchor_event()`, the newest accepted event at or before it, and is readable only where that
  event is: a client-chosen `at` whose anchor `can_see` rejects is `403 M_FORBIDDEN` (ADR-0414, the lower bound
  ADR-0084 lacked). Judge the anchor, never the members one by one: a roster holds members who joined before the
  caller, and a lookup per member under `runtime.mutex` is the F-10 cost. It gates `initialSync`,
  `/members`, `/joined_members` (current only), `/state`, `/state/{type}/{key}` and the `state` of
  `/sync`'s `rooms.leave` (ADR-0357).
- A user with no read access may still peek events (not `/members` or `/state`) when the
  room's **current** visibility is `world_readable` (`room_is_world_readable`); each event is
  still judged on its own state.
- `/messages` moves its token past hidden events and examines at most
  `ClientApiLimits::max_messages_events_examined` events per page.

Tests that write events straight into a `PersistentStore` must record a state group for them
(`tests/support/RoomHistoryFixture.hpp`), or the filter hides them.

## Device lists

`changed` and `left` name *users*, not change events: a user appears at most
once across both lists however many rows the store holds for it in the range —
spec: client-server-api.md, "Extensions to /sync".

An initial sync (`since` absent, or a sliding sync with no `pos`) deliberately
reports the full set rather than nothing, so a freshly logged-in device is
prompted to `/keys/query` its own user's devices straight away. The spec permits
either ("the server need only populate this property for an incremental
`/sync`"); this project chose to populate, and
`tests/integration/test_sync_handler_flow.cpp` pins that behaviour. Deduplication is what
keeps the initial response bounded.

All three surfaces that report device-list changes — `/sync`, the MSC4186 e2ee
extension, and `GET /_matrix/client/v3/keys/changes` — go through
`collect_device_list_delta` (`sync/DeviceListDelta.hpp`). It collapses the
store's append-only change log to one entry per subject user, so a subject is
never repeated however many rows the range covers, and resolves a subject that
both changed and left to whichever came last. Do not walk
`store.device_list_changes` directly.

Rows are written where a membership is applied to the roster, whichever path learned it:
`apply_membership_to_roster` (`RoomService.hpp`) records `changed` when a user joins and
`left` when they leave the last room they share with a local user, for local members of the
room and, when the user is local, for them. The membership acceptor (`send_join`,
`send_leave`) and `ingest_pdu_event` call it; a roster edit that skips it silently stops
`device_lists.left` for remote users. A user who joins over federation is also `changed` for
themselves (spec: a server may add a user to `changed` when they share a new room).

## Lazy-loading room members on `/sync` (ADR-0450 to ADR-0454)

`room.state.lazy_load_members` (never `room.timeline`'s) turns it on. `state` then carries the non-member state the room would carry without lazy-loading (the state filter and the incremental
delta still apply) and only
these `m.room.member` events, each passed through the state filter first: the senders of delivered timeline events, as of
the timeline's start; on a limited incremental sync every member change in the gap (never redundant); the user's own on an
initial sync, `full_state=true` or a join in the window, unless the join is in the timeline. All of it is decided by
`LazyRoomSelector` (`ClientServerRuntime.cpp`) inside the state builders; a sync that builds no state calls
`build_lazy_sender_members`. Look a member up by key (`member_event_at_timeline_start`), never by scanning the room's state.

`LazyMemberTracker` skips a member only when the client has acknowledged that exact event: an entry is recorded
pending, a request whose `since` equals its token exactly settles it (any other `since` deletes a pending entry; "at or
past" is not proof, a retried long-poll can answer past a token the client never received), and only a settled entry
whose token the `since` covers is redundant. A room the user just (re)joined does not consult the tracker.
`begin_request` runs after the long-poll wait and deletes entries `since` does not cover; `record_sent` runs after the
body is built. Its mutex is a leaf below
`homeserver.mutex`; do not call out of it or take another lock inside it. Do not replace it with a "sent" set (ADR-0450 has
the lost-response sequence that breaks it). `/messages` and `/context` stay stateless (ADR-0451). A change to a rule above
changes the tracker's tests with it.

## Long-poll behaviour

`sync_notifier` holds requests until an event arrives or `timeout` expires. A waiter names its user
(`SyncWaitParams::user_id`), and `publish` may name the users it affected (ADR-0437): a scoped publish wakes
those users' waiters, a publish with no scope wakes everyone. Scope a publish only when the affected set is certain
(`sync_audience_of_room`: the room's joined and invited members, the sender, the user a membership event is about);
receipts, typing, presence, device lists, account data, to-device, joins, leaves and the rest stay broadcasts. Never
read membership after publishing to decide whom to wake. Every publish moves generations even when the positions
did not advance (callers publish the visible position read at publish time, which can equal an earlier publish's); a scope
that is present and empty moves positions only. `PublishedStreamOrdering` (the reservation an inbound PDU holds while it
commits) ends with a broadcast when the visible position then passes its ordering (events were held behind it) and with an
empty scope otherwise; the PDU's own scoped publish does the waking, so a new path that stores an event under one publishes
its own scoped wake after the event is applied. A long-poll for a user takes a cursor (`observe`) and waits on
it; it is rerun only when its user's generation or the broadcast generation moved, never for the positions moving. All
three transports run `long_poll_wait`: cursor, then the positions check, then the rerun, and after a wake the NEW cursor
before the rerun, so a publish between the two costs one extra rerun, never a lost one. Do not erase a user's entry when
its last waiter leaves: a publish between two slices must be seen. The audience reads the room's rows through
`for_each_room_membership_row` (ADR-0437).
- The sliding-sync relevance check (`has_relevant_event` and the receipt and typing predicates) tests rooms against one set of the caller's joined rooms built from `for_each_user_membership_row`, walks at most `sliding_sync_relevance_scan_rows` events, and treats reaching that cap as relevant (answer, never park, so no wake-up is lost and the next poll's walk is short). Never call a per-event `user_is_joined`-style scan of `memberships` there (ADR-0609).
- A long-poll on the `sync_pool` path does not wait on a pool thread (ADR-0569): it parks in `ParkedPollRegistry`
  (owned by `SyncNotifier`) and is resumed on the pool by a publish for its user or by its deadline. Park with a cursor
  taken before the last rerun (`SyncNotifier::park` inserts, then compares the cursor), keep the registry mutex a leaf
  (publishers call `wake_users` / `wake_all` after releasing the notifier mutex), and never answer from the registry.
  A client that disconnects while parked is found when it resumes or at its deadline. When the registry refuses (full,
  stopping) or there is no dispatcher, the old in-thread wait runs: 1-second slices with a peer peek, from the cursor
  already held. The no-pool fallback and the sliding-sync re-wait loop wait for the full remaining timeout in a single call
- The sync thread pool (`sync_pool`) is separate from the main thread pool to prevent
  long-polling clients from starving federation and other short-lived requests

## Key spec sections

- [Syncing](../../docs/matrix-v1.19-spec/client-server-api.md#syncing)
- [Filtering](../../docs/matrix-v1.19-spec/client-server-api.md#filtering)
- [MSC4186 Simplified Sliding Sync](../../docs/matrix-v1.19-spec/client-server-api.md)

## Redactions are withheld until they apply (CSAZ-11)

`HistoryVisibility::can_see` returns false for an `m.room.redaction` event that has not been applied
(`database::redaction_is_withheld`): rooms/v3.md "Handling redactions" says a redaction is not sent to clients
until both it and its target have been received and it would be applied. Every read path that returns events
already goes through `can_see`, so a new one gets this for free; do not add a path that bypasses it. Events a
redaction has been applied to are stored in their redacted form, and the serializers add
`unsigned.redacted_because` with `database::attach_redacted_because` (a new client-facing event serializer must
call it, and `database::add_redaction_compat`).

## Receipts are read through the store's receipt indexes (ADR-0651)

Never loop `store.receipts` in a request: use `database::receipts_in_room` (ephemeral `m.receipt` events, the sliding
sync receipts extension and its wake check) or `database::receipts_of_user_in_room` (`read_markers_for`, the push badge
count). A threaded receipt (`thread_id` other than `main`) is accepted by the POST handler only for the thread root or
an event that belongs to that thread (`receipt_event_is_in_thread`), and `store_receipt` caps a user's threaded rows in
a room. A test proves cost with `receipt_rows_examined`, not time.

## Classic sync reads per-room rows through the room indexes (ADR-0654)

`sync_json` reads a room's state through `find_current_state_event_id` / `for_each_room_state_row`, its memberships
through `for_each_room_membership_row` and its receipts through `receipts_in_room`; never loop `store.state`,
`store.memberships` or `store.receipts` per room. Joined rooms that pass the room filter are counted in
`processed_rooms` before any per-room work and the loop stops at `max_sync_rooms`. Tests prove cost with
`state_rows_examined`, `membership_rows_examined` and `receipt_rows_examined`.

## An unread count parses a bounded number of bytes (ADR-0655)

`count_unread_by_thread` spends each classified event's JSON size, and `event_thread_id` each parent it parses, from
`max_unread_bytes_parsed` (512 KiB); when the next event does not fit the count stops and is a lower bound, as at
`max_unread_rows_examined`. Any new reader that parses sender-sized events per room takes a byte budget too. In
`sync_json` the "nothing new" check for a room runs before its counts.

## Room reads that skip rows a reader may not see take an examination budget (ADR-0656)

`/context` (each side of the event) and `/initialSync` walk `room_in_stream_order` in place and count every row they look
at, visible or not, against `max_messages_events_examined`, as `/messages` does; when it ends a walk early the `start`
or `end` token is the last row examined. Never copy a room's events into a vector to step through them.

## Every list of a sync filter is capped (ADR-0657)

Each list (`types`, `not_types`, `senders`, `not_senders`, `rooms`, `not_rooms`, `event_fields`) holds at most
`max_filter_list_entries` (100). `filter_list_cap_problem` finds an over-cap list in an uploaded, inline or stored filter;
`GET /sync`, `/messages`, `/context` and the upload call it and answer 400 `M_INVALID_PARAM`. The lenient parsers do
not refuse, and a new endpoint that matches a filter's lists against rows with a plain scan calls it too.


## Which joined rooms a classic sync serves (ADR-0658)

`select_sync_rooms` finds the candidate rooms from the user's own `join` membership rows (never by walking every room on
the server), and an incremental sync drops a room that cannot have news (no event, typing change, account-data row or
receipt above `since`) before it is charged to `max_sync_rooms`. Past the cap the most recently active rooms are served and
a room with news beyond it is skipped, as it always was. A new source of room news must be added to the check, or a room
whose only news it is would be dropped.
