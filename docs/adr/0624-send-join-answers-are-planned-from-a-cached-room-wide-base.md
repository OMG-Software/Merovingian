# Send_join answers are planned from a cached room-wide base

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, resource-exhaustion.send-join-acceptor.answer-plan-per-request-under-runtime-mutex

## Context and Problem Statement

`plan_send_join_answer` walks a room's whole state and auth DAG, and every send_join paid for it under `runtime.mutex`:
a resend, and a join refused because its answer is too large. At the per-origin rate a remote server could take most of
the lock with a large room. The plan cannot simply be cached whole: it depends on the joiner (heroes, `servers_in_room`, a
resend's own state row) and on the join's `auth_events`, and a remote server chooses both, so a cache keyed on them is
never hit by a server that varies them.

## Considered Options

* Build the plan outside the lock
* Cache whole plans per (room, state, user, auth events)
* Cache the room-wide part per room and state, and derive each request's plan from it

## Decision Outcome

Chosen option: a `SendJoinPlanBase` per (room, `omit_members`) in `SendJoinPlanCache`, and a per-request derivation.

* The base holds what no request changes: the state list, the auth walk from it with each event's size, which events are
  cited, and, for `omit_members`, the first roster members and the servers with their member counts.
* `derive_plan` looks only at what a request changes: its join's auth events and what they reach that the base did not, a
  resend's own row and the row before it, the heroes. It must hold the same IDs as `plan_send_join_answer`, which stays
  as the path for an untrusted state index and as the reference the tests compare with. Only the order of the auth chain
  can differ, which the spec does not fix.
* A base is valid for one `SendJoinPlanStamp`: `database::room_state_revision`, the room's state rows, the roster size
  and the size limits. An event a base found missing is looked up on each use, since it can arrive with no state change.
  The row count is in the stamp so that a writer which removes a row is noticed even if it moves no revision.
* A base whose smallest possible answer cannot fit keeps only that verdict (`sizes_only`), so a room too large to answer is
  remembered in a few bytes and every request for it is refused at once.
* The state before a stored join is remembered per event, since a state group never changes, so a resend skips
  `compute_state_before` too.
* The cache has its own mutex (ADR-0525) held across build and use, so a base cannot be evicted while it is read and
  nothing shares ownership of one. It is bounded by entries (32), estimated bytes (64 MiB) and memo rows (131072).
  Lock order: `runtime.mutex`, then the cache's.

Building outside the lock was rejected: the walk reads the store the lock protects, and copying the store out costs what
it saves. Caching whole plans was rejected for the reason above.

### Negative Consequences

* An accepted join changes the state, so it still pays for one build; those are limited by real, authorised joins.
* A delivered answer still copies its events out under the lock (`collect_send_join_answer`), linear in the answer and at
  most `join_response_max_size`. Only the planning is removed.
* The first request after any state change builds again, so a busy large room gains less than a quiet one.
* A writer that changes a current state row must move the room's revision. The two writers in `PersistentStore.cpp` do.

## Links

* Refines [ADR-0366](0366-a-send-join-is-refused-before-it-is-stored-when-its-answer-cannot-be-delivered.md)
* Relates to [ADR-0525](0525-a-cache-that-is-not-thread-safe-is-not-hidden-behind-const.md)
