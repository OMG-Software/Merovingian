# A due delayed event is sent by one job through the ordinary send path, never early and at least once

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

A delayed event ([ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md))
is stored with a deadline. Something must send it when the deadline passes, as the user, authorised against the room
as it is then. The spec requires that it is never sent early, asks for it within 30 seconds, requires the per-user
rate limit to apply, and says a failed send is cancelled with the error stored. Who sends it, with what checks, and
what happens when the server stops between sending and recording?

## Decision Outcome

Chosen option: "one `PeriodicJob` that sends through `send_event_as_user`", because it reuses the ordinary send path
and its authorisation, and the job machinery already sleeps until a deadline.

* A `PeriodicJob` named `delayed-events` is created in `src/main.cpp` beside `typing-expiry`, started after process
  hardening, stopped on shutdown in the same sequence as the other jobs, and refuses to serve if its thread cannot
  start. `HomeserverRuntime::delayed_events_wake` (null in tests, installed and removed under the runtime lock like
  `typing_expiry_wake`) is called when an event is scheduled. A restart only moves a deadline later and needs no wake.
* The body is a function taking the runtime, `now_ms` and the stop flag. Per run: take the runtime lock, ask the table
  for the earliest-due scheduled row with due time at or before `now_ms`, send it, release the lock; one send per
  lock hold, the stop flag checked between items, at most 100 sends per run (then it runs again at once). One age
  prune batch, in its own lock hold. It returns the time until the next due row, clamped to 0 to 60 seconds, and 60
  seconds when nothing is scheduled.
* Time is wall-clock milliseconds, because the due time is persisted and must mean the same after a restart. Handlers
  and the job take "now" from one function that honours a `HomeserverRuntime` test seam. Tests drive the job body with
  a chosen `now_ms` and never sleep; no test depends on a wall-clock margin.
* Never early: the job sends only when `now_ms >= delayed_since_ms + delay_ms`, both read under the lock at the
  moment of sending. Events that fell due while the server was down are sent by the first run after start-up.
* One send, under the runtime lock: re-read the row (still scheduled, not being sent); apply the account checks the
  request gate would apply (unknown or deactivated `M_USER_DEACTIVATED`, locked `M_USER_LOCKED`, suspended
  `M_USER_SUSPENDED`); apply the per-user rate limit with one `RateLimitEngine::check` with an empty address bucket
  and the per-user key and policy of the ordinary `/send` or `/state` template; build the event body with the
  ordinary route's helper; call `send_event_as_user`. The event is therefore authorised against the room state now,
  signed, persisted, federated, pushed and published to `/sync` like any other.
* Success finalises the row as sent with the event ID. Failure finalises it as failed with the standard error object.
  A failed send is never retried.
* The `send` action runs the same steps inside the request; on failure it answers with the send's own status and
  error and leaves the row scheduled; a rate-limit denial there is `429 M_LIMIT_EXCEEDED` with `retry_after_ms`.
* Exactly one sender at a time: the job and the `send` action both run under the runtime mutex and re-read the status
  under it. The row is also marked "being sent" (memory only) before `send_event_as_user` is called and unmarked when
  it returns, and while it is marked the row is out of the due order and a second send, restart or cancel answers
  409.
* At least once: the order is send, then finalise. The event's commit and the row's update are two transactions; a
  crash between them sends the event again after restart. For a call membership leave a duplicate is harmless and a
  lost one is the bug being fixed.
* If the finalising commit fails after the send was attempted, the in-memory row is finalised anyway and the failure
  is logged. Memory then says what happened, the database row still says `scheduled`, and the next start-up sends it
  again. Leaving the memory row scheduled would send it again on every run. This is the only place the mirror changes
  without a successful commit, and the code says why in a comment.

## Pros and Cons of the Options

### Record as sent, then send (at most once)

* Bad, because a crash between the two loses a call's leave.

### Put the row's update in the event's own transaction

* Bad, because it would change how ordinary sending works.

### Retry a failed send

* Bad, because the spec says cancel and store the error, and an authorisation failure would retry for ever.

### A grace period after start-up before sending overdue events

* Bad, because a vanished client's membership would outlive the restart by the grace. The spec asks only for "never
  early", and the reference server sends at once.

### A steady (monotonic) clock

* Bad, because the deadline must survive a restart.

### A thread or timer per event

* Bad, because `PeriodicJob` already sleeps until the earliest deadline and can be woken.

### Sending without re-checking the account

* Bad, because the lock, suspension and deactivation refusals live only at the request gate, so the job must apply
  them itself, as the profile propagation job does.

### No send-time rate limit

* Bad, because the spec requires one. The engine's per-user bucket for the ordinary route is consulted with no client
  address, which is a no-op unless an operator configured a per-user policy for sending.

### A full dry run when an event is scheduled

Compose and sign, then discard.

* Bad, because it would need the ordinary send split in two. The schedule-time check is membership plus, for state,
  `may_send_state_event`; the real authorisation is at send time.

## Consequences

* The delayed-events job is the only background sender of delayed events.
* Anything inside the send path that releases the runtime lock is covered by the "being sent" mark. A change that
  makes the send path release the lock for a new event type must keep the mark set across it.
* A clock stepped backwards delays sends; stepped forwards, it brings them forward by the step. The server has no
  other persistent clock.
* The one place an in-memory row changes without a successful commit is after a send attempt, for the reason above;
  do not add another.
* Tests drive the job body with a chosen `now_ms` and never sleep.

## Links

* Related: [ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)
* Related: [ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md)
* Related: [ADR-0353](0353-a-profile-change-holds-the-runtime-lock-for-a-fixed-share-of-the-users-rooms.md)
