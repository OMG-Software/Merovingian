# The sync notifier wakes a long-poll for its own user, and a publish with no scope wakes everyone

* Status: accepted
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

Chosen option 2. `publish(stream_ordering, sync_stream_id, scope)`: with no scope it is a broadcast (every waiter wakes);
with a scope, only the waiters of the named users (and any waiter that named no user) wake. A waiter passes its user to
`wait_for_change`. The positions, the per-user generations and the waiters are one mutex's state, and the entry check
against `since` and the waiter's registration happen in one hold of it, so no publish can fall between them. The scope is
passed in as data: the notifier never reads room membership.

Only a publish whose affected set is certain is scoped (`sync_audience_of_room`: the room's joined and invited members, the
sender, and the user whose membership the event changes, including one it removes): `send_event_as_user`,
`store_composed_membership` and the federation PDU sink. Receipts, typing, presence, device lists, account data, to-device,
joins, leaves, forgets, knocks, room creation and profile changes stay broadcasts. A new publish site stays a broadcast until
someone can show the set exactly.

An out-of-scope waiter is not woken, but its next `wait_for_change` starts from the same `since`, so it returns at once if
a position moved while it slept (the immediate return that makes a publish made before the wait correct). Its handler then
finds nothing and re-waits, as before; it is at most once per slice, not once per event.

### Consequences

* A waiter that names no user wakes on every publish, as before.
* `signals_sent()` counts waiters signalled, so a test proves a wake-up was withheld without sleeping.
* Advancing the long-poll cursor after a quiet slice (so the immediate return does not fire for out-of-scope events) is a
  possible follow-up; it needs the notifier to return its positions.
