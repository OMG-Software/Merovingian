# The sync notifier wakes a long-poll for its own user, and a publish with no scope wakes everyone

* Status: accepted; the 1 s slice wait is superseded by [ADR-0569](0569-a-long-poll-with-nothing-to-return-parks-in-a-registry-and-gives-up-its-sync-pool-thread.md) (the scoped-wake decision stands)
* Date: 2026-11-04

Technical Story: performance defect P4 of the 2026-11-04 project analysis (every event wakes every long-poll)

## Context and Problem Statement

`SyncNotifier::publish` called `notify_all()` and each waiter's predicate was "a global position moved", so an event in
one room woke every parked `/sync`, each of which then rebuilt its response under `runtime.mutex`.

## Decision Drivers

* A lost wake-up is the failure to avoid: a client that misses its event waits out its timeout.
* The notifier must stay correct for callers that cannot name who a change concerns.
* Shutdown and dropped-client detection (1 s slices in `http_server.cpp`) must not change.

## Considered Options

1. Per-room notification, waiters subscribing to rooms.
2. Per-user generation beside the global positions; `publish` optionally names the affected users.
3. Keep the broadcast and make the handler cheaper.

## Decision Outcome

Chosen option 2. `publish(stream_ordering, sync_stream_id, scope)`: with no scope it is a broadcast (the broadcast
generation moves and every waiter wakes); with a scope, the generation of each named user moves and only that user's
waiters (and any waiter that named no user) wake; a scope that is present and empty moves the positions only and wakes no
user. Every publish moves generations, whether or not the positions advanced: every caller publishes the visible position
read at publish time, so one writer's publish can carry the position of another writer's event, and a publish that did not
look like an advance would otherwise lose its wake-up. Equal or lower positions are still ignored for the counters (the
position-overload waiters wake only on an advance). A user with no entry has never observed, so there is no cursor to miss
the publish. The notifier never reads room membership: the scope is passed in as
data, taken by the caller under `runtime.mutex` at the publish site.

A long-poll for a user holds a cursor (`observe(user)`: the user's generation and the broadcast generation, taken under
the notifier's mutex) and waits on it (`wait_for_change(cursor, timeout)`), which returns true when either generation has
moved past the cursor, whether the move happened during the wait or between two waits, and ignores the positions.
A user's generation is kept for the notifier's life, not erased when the last waiter leaves, so a publish landing between
two 1 s slices is not lost; the map is bounded by the local users who long-poll. `long_poll_wait` is the one sequence all
three transports run: (a) take the cursor; (b) if the positions are already past `since`, rerun once (its snapshot is
after the cursor); (c) loop: wait on the cursor for a slice, and on a change take a new cursor and THEN rerun, so a publish
between the two causes at most one harmless extra rerun, never a lost one; on a quiet slice the transport's idle check
(the peer peek) runs. Shutdown (`running`) and the 1 s slice are the transport's. A waiter that names no user keeps the
position behaviour and wakes on every publish.

### Ending a stream-ordering reservation (`PublishedStreamOrdering`)

An inbound PDU reserves its stream ordering, commits with `runtime.mutex` released and applies. Ending the reservation moves
the visible position past events that were applied behind it. Its destructor therefore reads `visible` after releasing: if
`visible` is above the released ordering it publishes with no scope (a broadcast); otherwise it publishes an empty scope
(positions only). The PDU's own scoped publish (`pdu_sink`) wakes its room's audience. Why no wake-up is lost: an event not
visible at its own scoped publish has an ordering above some pending ordering; when the last such pending ordering ends,
`visible` reaches at least that event's ordering, which is above the ordering just released, so that release broadcasts. An
event that is visible at its own scoped publish wakes its audience there, because every publish moves generations. An early
wake finds nothing and sleeps again. With 5, 6 and 7 pending and released 7, 6, 5, the first two release nothing (the oldest
is still pending, `visible` stays 4) and the third broadcasts (`visible` is 7, above 5). A reservation whose commit failed
holds nothing behind it and wakes no user. A path that relied on the destructor to wake anyone needs its own publish after
its event is applied.

Only a publish whose affected set is certain is scoped (`sync_audience_of_room`: the room's joined and invited members, the
sender, and the user whose membership the event changes, including one it removes): `send_event_as_user`,
`store_composed_membership` and the federation PDU sink. Receipts, typing, presence, device lists, account data, to-device,
joins, leaves, forgets, knocks, room creation and profile changes stay broadcasts: their affected sets are not computed at
the publish site today (a receipt or typing change concerns the room's members across servers, a to-device message one
device, account data one user, and each is published from code that has no audience helper), so a broadcast is the safe
answer. Federation PDUs are scoped by the `pdu_sink`; events held behind an older pending ordering are announced by a
broadcast when that ordering ends. A new publish site stays a broadcast until
someone can show the set exactly. The audience reads the room's membership rows through a per-room index of
`PersistentStore::memberships` (`for_each_room_membership_row`), so an event send does not scan every room's memberships.

### Consequences

* A waiter whose positions were overtaken by publishes for other users is not rerun; it runs the sync again only for a
  change that concerns it, a broadcast, or the deadline.
* A waiter that names no user wakes on every publish, as before.
* `signals_sent()` counts waiters signalled (users with a parked waiter), so a test proves a wake-up was withheld
  without sleeping.
