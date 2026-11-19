# Unexpired sticky events skip history visibility, reach every client whole, and follow MSC4508 scope

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

The first sticky events change
([ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md) to
[ADR-0857](0857-a-room-holds-a-bounded-number-of-sticky-events-shared-fairly-between-servers.md)) left five places
where it did less than MSC4354, MSC4480 and MSC4508 ask:

* MSC4354: "History visibility checks MUST NOT be applied to unexpired sticky events. This applies to all endpoints"
  and "Any joined user or server is authorised to see unexpired sticky events for the duration they remain sticky".
  Only the `/sync` section skipped the check: `/event`, `/context`, `/messages` and the federation reads still hid a
  sticky event from a user or server that joined after it under `joined` or `invited` visibility.
* Classic `/sync` sent only the newest 100 of a room's sticky events. MSC4354 requires every unexpired sticky event to
  be delivered, and classic `/sync` has no cursor for the rest, so the older ones were never sent.
* MSC4480 counts the senders of the sticky events sent as timeline senders for lazy-loaded members. Sliding sync sent
  the events without their senders' member events.
* An event chosen for a section could expire before it was serialized and be sent with no remaining time, as if it
  were not sticky.
* MSC4508's `lists` key, which names the lists an extension applies to, was ignored, and `rooms` was read as "any room
  named" instead of "the room subscriptions named".

## Decision Drivers

* A call membership is what a client reads to show who is in a call. A user who joins mid-call must see it.
* Each surface must stay bounded per room and per request.
* The federation worker has no database: what it serves comes from main's room snapshots
  ([ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md)).

## Considered Options

* Skip history visibility in the sync sections only, as before.
* Skip it in `HistoryVisibility::can_see` and the federation server filter, for a user or server joined now.
* Keep a classic `/sync` cap of 100, or add a sticky cursor to the stream token.
* Drop the cap and let `server.sticky_events.max_per_room` bound the section.

## Decision Outcome

Chosen options: skip the check in the two filters, and drop the cap.

* **Client reads.** `HistoryVisibility::can_see` answers yes, before the five rules, for an `accepted` event that has
  an unexpired sticky row of the event's own room, when the user's current membership of that room is `join`. A
  withheld redaction is still withheld, and nothing else changes: a rejected, soft-failed or expired event, or a user
  who has left, is judged by the rules as before. The sticky clock is read once per filter, so one request judges
  every event at one instant.
* **Federation reads.** `ServerEventFilter::can_see` (`/event`, `/backfill`, `/get_missing_events`) does the same for
  an origin with a user joined to the room now. A federation worker reads the sticky rows from its snapshot: a room
  snapshot carries the room's unexpired rows, `apply_room_snapshot` replaces the room's rows with them, and
  `fill_store_from_room_snapshots` inserts them. Main notifies the worker after it commits a row, as for any room
  change. The worker never records, deletes or pushes a sticky row; expiry is judged by its own clock.
* **Classic `/sync`** sends every unexpired sticky event the response chooses. A room holds at most
  `max_per_room` (default 1000, at most 10,000) unexpired rows, so the section is bounded without a cap of its own and
  without a token change.
* **Sliding sync lazy members.** When a list or subscription lazy-loads members, the senders of the sticky events a
  response sends get their member events in `required_state` as timeline senders do, once per connection, and a room
  whose only change is those member events is still sent.
* **Expiry during a request.** An event is added to a section only when its serialized form carries
  `sticky_duration_remaining_ms` (`database::carries_sticky_remaining`). An event that expired after it was chosen is
  left out and not recorded as delivered.
* **Scope (MSC4508).** `sync::extension_scope_rooms` is the one place an extension's scope is decided. A room is in
  scope when it is within the range of a list `lists` names, or is a room subscription `rooms` names. An absent key
  names every list or subscription, `[]` names none, and an entry `"*"` names every one (the older MSC3575 form). A
  room named in `rooms` without a subscription is not in scope. The caller then keeps only the rooms the user has
  joined.

### Positive Consequences

* A user or server joining a call sees every current call membership on every endpoint, and a classic `/sync` client
  gets all of them.
* The worker and main give the same answer for a sticky event.

### Negative Consequences

* A user who joins a room can read its unexpired sticky events from before the join, whatever the history visibility.
  That is what MSC4354 asks, for at most an hour after each event was seen.
* A classic `/sync` section can hold up to `max_per_room` events, ten times the previous cap.
* Only `sticky_events` reads `lists`. The typing and receipts extensions still read `rooms` as before.

## Pros and Cons of the Options

### Skip history visibility in the sync sections only

* Good, because nothing outside `/sync` changes.
* Bad, because MSC4354 says the rule applies to all endpoints. A client that fetches a call membership by ID (a reply,
  a relation) would get 404.

### Keep the classic `/sync` cap of 100

* Good, because the section stays small.
* Bad, because the older events are never sent: classic `/sync` has no cursor for them. A sticky cursor would change
  the token every client holds (rejected in
  [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)).

## Links

* Amends [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)
* Amends [ADR-0857](0857-a-room-holds-a-bounded-number-of-sticky-events-shared-fairly-between-servers.md)
* Related: [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md)
