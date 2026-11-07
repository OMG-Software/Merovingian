# A long-poll with nothing to return parks in a registry and gives up its sync-pool thread

* Status: accepted; supersedes the 1 s slice wait of [ADR-0437](0437-the-sync-notifier-wakes-a-long-poll-for-its-own-user.md) (its scoped-wake decision stands); amends [ADR-0077](0077-no-worker-waits-on-a-quiet-connection.md) (a connection gains a fourth owner) and [ADR-0091](0091-bound-sync-waits-with-admission.md) (the global admission cap is no longer clamped to the pool, see [ADR-0570](0570-sync-max-in-flight-bounds-parked-waits-not-pool-threads.md))
* Date: 2026-11-07

Technical Story: project analysis finding P15a (each long-poll holds a sync-pool thread for its whole timeout).

## Context and Problem Statement

A `/sync` whose first pass has nothing to return was handed to the sync pool, where one thread waited on the
`SyncNotifier` in 1 s slices (a `recv(MSG_PEEK)` on each quiet slice detected a dropped client) until a publish
that concerned the user or the deadline (at most 120 s). So the number of concurrent long-polls was the number of sync
threads (128 by default); one more was refused with 429, and a larger pool only moves the limit while costing a
stack and a thread per idle client. How does a quiet long-poll stop costing a thread, without losing a wake-up,
without a lock-order inversion and without a connection that nobody answers?

## Decision Drivers

* A lost wake-up costs the client its whole timeout; a lock-order inversion is a production hang.
* ADR-0077 rule 7: a connection is owned by exactly one party, moved as a `std::unique_ptr`, TLS included.
* A request is never run on the thread that publishes (it holds `runtime.mutex` and the notifier is called from it).
* Shutdown is bounded and a hang in a test is a failure.
* No new thread before hardening (ADR-0082); no new config key if an existing one will do.

## Considered Options

1. **Park the connection in a registry of the notifier; a publish or the deadline resubmits it to the sync pool
   (chosen).**
2. Make the sync handler asynchronous (a reactor). Rejected: handlers are synchronous and hold the runtime lock
   (ADR-0077's own reason).
3. Give the existing `net::ConnectionParker` the waiting connections. Rejected: it wakes on socket readability, not
   on a notifier publish, and caps by pool workers and client shares; a long-poll needs the opposite wake source and
   a per-user index.
4. A larger sync pool. Rejected: it moves the limit and spends a thread per idle client.

## Decision Outcome

Chosen option 1. Each rule below is something a later change could undo by accident.

**Parts.** `sync::ParkedPollRegistry` (`include/merovingian/sync/`) is owned by `SyncNotifier` (a member, so a
publish reaches it without a registration that could dangle) and holds *parked polls*: an opaque
`std::unique_ptr<sync::ParkedPoll>` (the HTTP layer derives `ParkedSyncPoll` from it; destroying it closes the
connection and releases its admission slots), the waiting user, and a deadline. It has one thread, started by
`HttpConnectionDispatcher::start()` (after hardening) with a resume callback that submits to the sync pool.

**Ownership transfer.** A connection is owned by exactly one of: the dispatcher's `ConnectionParker`; a main-pool
task; a sync-pool task; or the registry. Every move is a `std::unique_ptr` move. `SyncNotifier::park` and
`ParkedPollRegistry::park` take the poll by reference and move from it only on success, so a refused park leaves
ownership with the caller, who answers or waits in its own thread. The registry never touches the connection: it
hands the poll back out only through the resume callback, on its own thread, with no lock held. The callback
moves it into a sync-pool task (carried in a shared holder because pool tasks are copyable `std::function`s, as
ADR-0077 describes) and, if the pool refuses or is stopped, destroys it, which closes the connection. The user and
device admission slots live in the poll and so are held while parked: parked polls count toward the per-account and
per-device caps exactly as running ones did.

**Wake protocol (no lost wake-up).** The task that ran the request (a) takes the user's cursor with
`SyncNotifier::observe` BEFORE the rerun whose answer was "nothing", (b) reruns, then (c) parks with that cursor.
`SyncNotifier::park` does, in this order and with no lock held across the steps: insert into the registry (registry
mutex), then compare the cursor with the notifier's generations (notifier mutex); if either has moved, wake the
just-inserted entry at once. A publish does: move the generations (notifier mutex, released), then tell the registry
which users it concerned (`wake_users`, or `wake_all` for a publish with no scope; registry mutex). Either the
publish's registry step is after the insert (it finds the entry), or it is before it, in which case its generation
move happened before the insert and so before the cursor comparison, which sees it. The two cannot both be missed.
An early or doubled wake finds nothing and parks again (ADR-0437); waking an id that is no longer parked is a no-op.
A woken poll is *resumed*, never answered by the registry: the resume task takes a fresh cursor, THEN reruns with
`can_wait`, answers if the rerun completes and parks again (with the new cursor and the rerun's positions) if it
does not. Only a publish scoped to other users leaves it asleep, as before.

**Lock order.** `runtime.mutex` -> `SyncNotifier::mutex_` is never nested by this change and
`runtime.mutex` -> `ParkedPollRegistry::m_mutex` is allowed because the registry mutex is a leaf: while holding it
the registry only edits its own containers and notifies its own condition variable. It never takes the notifier's
mutex, `runtime.mutex`, the dispatcher's lock or the pool's, never destroys a poll (destroying one closes a
socket and releases budgets), never calls the resume callback and never runs a request. Publishers call into the
registry after releasing the notifier's mutex, so the notifier's and the registry's mutexes are never held
together. A request therefore never runs on a publishing thread: the publisher moves entries to a ready queue and
signals; the registry thread submits.

**Deadline timer.** One thread, the registry's, keeps entries in a `std::multimap` ordered by deadline and a hash
index by id and by user; insert and removal are O(log n) and O(1) per user entry. It sleeps until the earliest
deadline or a signal. An expired entry is resumed with `WakeReason::deadline`: the task makes the final rerun with
`can_wait` false and answers whatever is there (the same as the old end of the loop). The timer thread performs no
I/O and no request.

**Disconnects.** A parked poll is not polled. A client that goes away is detected when its entry next resumes (the
resume task peeks the socket first, as the slice loop did, and closes without logging a completed request) and at
the latest at its deadline, so nothing outlives its deadline. Admission caps bound how many a client can hold meanwhile.

**Bounds.** The registry refuses (caps `Limits`) past `sync_max_in_flight` parked entries, past `sync_max_per_user`
for one user, when stopped and when not started. On refusal the task keeps its thread and finishes the wait with the
slice loop of ADR-0437 (`long_poll_wait`, which this decision keeps for exactly this case and for transports with no
dispatcher), passing the cursor it already holds so no publish between the last rerun and the refusal is lost. So
past the cap we behave as before rather than answering early: an early answer with an empty body would make a client
spin. Per-client-address limits are untouched: the per-IP connection slot is a member of the connection and moves
with it, and the dispatcher's worker share was already released when the connection went to the sync pool.

**Shutdown.** `HttpConnectionDispatcher::request_stop()` stops the parker, then `ParkedPollRegistry::request_stop()`:
under the registry mutex it sets `stopping` and takes every entry (parked and ready) into a local list and
signals; it joins the thread (never called from that thread); then, with no lock held, destroys the list, which
closes every parked connection. It does not answer them: answering needs the runtime and pools mid-teardown, and
a client whose long-poll is cut reconnects, as it would after a restart. A task that tries to park after the stop
is refused and answers at once with a final rerun (no waiting). The stop is bounded by one thread join; nothing
waits on a client. The order in `main.cpp` is unchanged: dispatcher stop (parker, then registry), pools, runtime.
The resume callback captures the sync pool by pointer, so the registry is stopped before the pools are destroyed;
the dispatcher is declared after them.

**Sliding sync.** MSC4186 and classic `/sync` share the `needs_wait` path, the admission budgets and
`rerun_waiting_sync`, so both park through the same code. The transports with no sync pool or no dispatcher
(`dispatch_local_http_request`, direct `serve_one_http_connection` callers) keep the in-thread wait.

### Positive Consequences

* Concurrent long-polls are bounded by memory and `sync_max_in_flight`, not by the thread count.
* A quiet long-poll costs one registry entry and its socket; sync-pool threads only run requests.

### Negative Consequences

* A woken poll is rerun from the start on a (possibly different) pool thread; the request is rebuilt as before.
* A disconnected parked client keeps its socket and admission slots until its next wake or its deadline (at most
  120 s), where the slice loop noticed within 1 s. The per-user and per-device caps bound it.
* Shutdown closes parked polls instead of answering them.

## Links

* Supersedes the slice wait described in [ADR-0437](0437-the-sync-notifier-wakes-a-long-poll-for-its-own-user.md).
* Amends [ADR-0077](0077-no-worker-waits-on-a-quiet-connection.md), [ADR-0091](0091-bound-sync-waits-with-admission.md).
* [ADR-0570](0570-sync-max-in-flight-bounds-parked-waits-not-pool-threads.md).
* Tests: `tests/unit/test_parked_poll_registry.cpp`, `tests/integration/test_parked_long_poll_flow.cpp` (`[p15a]`).
