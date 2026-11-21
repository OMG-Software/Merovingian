# The first presence change in a five-second window is kept, and every other one in it is dropped

* Status: accepted
* Date: 2026-11-21

Technical Story: the presence loop of ADR-0871. Even with the devices combined, anything that changes an account's
presence many times a second (a buggy client, two clients fighting through `PUT /presence`) queues an EDU for every
server in the account's rooms each time.

## Context and Problem Statement

Every change of a local user's presence is stored, wakes the syncs of everyone who shares a room with them and queues
one `m.presence` EDU per remote server in those rooms, each in its own transaction. How often may one account cause
that?

## Decision Drivers

* One account must not be able to fill the federation dispatch queue.
* The owner's rule: the first change in a window goes through and the rest are dropped. Keeping the last change for
  later ("coalescing") is the same rate limit with a different change kept, and the last change is as likely to be the
  wrong one as the first.
* `PUT /presence/{userId}/status` has only 200 and 429 in the spec.

## Considered Options

1. A window of `change_window_ms` (5 s) per account, started by a change kept. A change asked for inside it is dropped
   (a sync: nothing stored, woken or sent) or refused (`PUT`: 429 `M_LIMIT_EXCEEDED` with `retry_after_ms` and
   `Retry-After`). Judged and noted under `runtime.mutex`, with the write.
2. Coalesce: hold the last change asked for in the window and send it when the window ends.
3. Limit only the outbound EDUs, and store every change.

## Decision Outcome

Chosen option: 1.

* The window is per account, not per device, since the row and its EDUs are per account.
* A change is a change of the stored state by a sync, or any `PUT`. A sync that leaves the state as it is refreshes the
  last-active time in memory as before and is not limited.
* Not limited: the idle sweep (the server's own change, at most once per idle period; a user who returns at once is
  marked online at once), the profile propagation that resends an unchanged presence with a new display name or avatar
  (it stores the row for local syncs and appservices and sends no `m.presence` EDU), and inbound presence from other
  servers (their own server's to limit).
* An account with an open window is never removed from `AccountPresenceTracker`, or removing it would lift its limit.
  A full table makes room by evicting an account with no open window (ADR-0871), so accounts that keep syncing never
  shut others out. Only when every account in it has an open window is a change of an account it does not hold refused
  (fails closed, as `UserCodeAttemptThrottle` does), so a flood of accounts cannot lift the limit for itself. The
  refusal's `retry_after_ms` is the rest of the soonest window (at most `change_window_ms`), and its log line's `cause`
  is `tracker_full`, not `window`.
* A dropped change is never kept later: a parked `/sync` or sliding sync is run again after a wake-up or its timeout
  (`rerun_waiting_sync`, `ClientServerDispatchOptions::sync_rerun`), and that rerun does not apply its `set_presence`
  again, so a change dropped in the window is not stored once the window has ended.
* Tests move the clock with `HomeserverRuntime::test_presence_clock_advance_ms`.

### Positive Consequences

* One account causes at most one presence broadcast every 5 seconds.

### Negative Consequences

* A change asked for in the window is lost, not deferred: a client that set `unavailable` a second after a sync set it
  `online` is refused, and its sync's next change is what counts.
* A client that does not retry a 429 on `PUT /presence` keeps whatever was set first.
