# Isolate push delivery capacity per recipient

* Status: accepted
* Date: 2026-10-14

Technical Story: OUT-3 in `docs/security-audit-report-2026-09-29.md`.

## Context and Problem Statement

The global push cap admits one task for an event's complete delivery vector.
That task contacts all recipients' gateways sequentially. One recipient can
therefore occupy every global slot across repeated events, or delay another
recipient in the same event vector. A real SQLite/public-dispatcher/loopback-TLS
regression reproduced cross-user starvation: its healthy notification control,
held attacker notification and cleanup passed, but the healthy notification
under attack was not dispatched.

This record covers recipient isolation only. The implementation is present;
normal integration passes 263 assertions / 1 isolation case and 1,092 / 18 related
push cases against sources stable during those runs. Independent source review
passed with no security or logic findings, and parent checks bind all four
reviewed production/test files to those runs and the scan. Fresh full acceptance
passed 56 targets, all return codes zero, no failures/timeouts and 170 unchanged
files including all 61 focused sources. Parent inspected fresh archived JSON/text
and review bindings before accepting this bounded slice and releasing the freeze;
only status docs changed afterward. Suggested tests still cover exception injection,
budget boundaries, concurrent admission and churn/retention. This does not close
OUT-3's separate gateway-circuit or pusher-registration requirements.

## Decision Drivers

* A single recipient must not consume all parallel delivery capacity.
* A stalled recipient must not delay a different recipient in the same vector.
* Keep the process-wide work bound, best-effort drop policy and nonblocking
  request path; do not introduce an unbounded retry or scheduling queue.
* Release admission on completion and exceptions without taking a mutex needed
  by a waiter, and without depending on when a future's shared state is destroyed.
* Preserve existing configuration, persisted pushers, outbound discovery/SSRF
  policy and rejected-pusher removal.

## Considered Options

* Keep globally capped, sequential event-wide tasks.
* Add a user counter but retain the mixed-recipient task.
* Split into recipient batches with global and per-recipient admission.
* Add a persistent fair scheduler and retry queue in this repair.

## Decision Outcome

Chosen option: "Split into recipient batches with global and per-recipient
admission". All entries for a recipient are processed sequentially in their own
background task. `server.push.max_in_flight_deliveries` counts running recipient
batches instead of event-wide tasks. A recipient's limit is at most eight and,
when the global limit exceeds one, at most the global limit minus one. No new
configuration key is introduced. At the default global limit of 256, the
recipient limit is eight; at a global limit of two, it is one.

Admission checks and increments share the dispatcher's existing orphan-future
mutex. Per-recipient counters are shared, atomic values; inactive map entries
are removed during admission/reaping. A move-only RAII permit releases both
counters without taking the runtime or orphan-future mutex. The task moves its
captured permit into a local guard, so release occurs when work completes, not
when a parked future is eventually destroyed. Parking storage is reserved before
launch so insertion cannot destroy a running future while a request lock is held.

At either limit, drop only the affected recipient's batch and continue considering
other recipients. This refines ADR-0028's accounting unit while retaining its
best-effort dropping and `/sync` recovery policy. ADR-0029's delivery truncation
and existing registration behavior are not superseded by this narrow repair.

### Positive Consequences

* With more than one global slot, one stalled recipient alone cannot exhaust
  the entire process budget.
* Different recipients of the same event no longer share sequential gateway work.
* Counter release does not acquire a completion-time mutex; failed launches and
  exceptions cannot permanently consume admission.
* Stored pusher identities and gateway transport policy need no migration.

### Negative Consequences

* Per-recipient overload can drop pushes sooner than the former global-only limit.
* A global limit of one cannot reserve parallel capacity for another recipient;
  its existing drop-at-cap behavior remains. Use at least two global slots when
  parallel isolation is required.
* Several recipients can collectively fill the global budget. This is not a
  fairness guarantee or a persistent scheduler.
* The fixed ceiling of eight is deployment policy, not a Matrix protocol maximum.
* Runtime moves remain startup-only, as with the existing captured-runtime
  background work. Moving a runtime while tasks run is not supported here.
* Gateway circuits, registration quotas, retries and full OUT-3 acceptance need
  separate repairs and execution evidence.

## Pros and Cons of the Options

### Keep event-wide tasks

* Good: retains the existing scheduling unit.
* Bad: global capacity and same-event head-of-line starvation remain.

### Add a user counter without splitting

* Good: limits repeated work for an individual recipient.
* Bad: ownership is ambiguous for mixed-recipient vectors and sequential gateway
  work still delays otherwise healthy recipients.

### Persistent fair scheduler and retry queue

* Good: could provide durable delivery and stronger scheduling guarantees.
* Bad: requires additional persistence, bounded queue admission, retry ownership
  and shutdown design; none is supplied by the current parked-future mechanism.

## Links

* Refines [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md).
* Retains the existing scope of [ADR-0029](0029-bound-pusher-delivery-rather-than-registration.md).
* Regression: `tests/integration/test_push_user_isolation_flow.cpp`.
