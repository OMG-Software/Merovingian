# Bound send_join key fetches by the shared in-flight cap, waiting for a slot

* Status: accepted
* Date: 2026-10-16

Technical Story: 29 September 2026 security audit, finding FED-10, as reopened by the review of PR #509.
Follows [ADR-0132](0132-separate-cached-verification-keys-from-budgeted-discovery.md) to
[ADR-0135](0135-preserve-key-admission-denial-through-backfill-recovery.md) and
[ADR-0153](0153-split-key-resolution-budgets-across-worker-shards.md).

## Context and Problem Statement

When a local user joins a room through a resident server, `filter_verified_send_join_events` verifies the
signature of every event in the `/send_join` response's `state`. That needs the signing key of every
server that sent one, which for a large room is thousands of servers. It called the raw
`remote_key_resolver` directly, up to `join_state_key_parallelism` (100, at most 1024) at once, outside
the in-flight cap, the per-source rate and the server/key failure cache that every other network key
resolution is admitted against. A hostile resident server could name thousands of invented servers and
drive a burst of outbound discovery and key fetches that none of the FED-10 budgets saw.

The other paths refuse a resolution over budget: the request is retried by its sender, so refusing is
load shedding. A join is not retried that way. A refused key here means the event it verifies is dropped as
unverified, and the joined room's state is incomplete.

## Considered Options

* **Share the in-flight cap and the failure cache, and wait for a slot (chosen).**
* Full admission through `resolve_verification_key`, refusing over budget. Rejected: at the default
  per-source rate (30 a minute) a room with more than a few dozen servers would lose most of its member
  events, a correctness bug in exchange for a resource bound.
* Leave the path unbounded and record it as a residual. Rejected: the burst stays possible, and the
  claim that every network key resolution is bounded stays false.

## Decision Outcome

Chosen option: `federation::resolve_join_state_key`.

* A network-free cached key (`cached_pdu_key_lookup`) is used without a slot.
* Otherwise the fetch takes one of this runtime's `key_resolution_max_in_flight` slots, the same counter
  every other resolution is admitted against, so the process never has more key fetches in flight than
  the cap, whatever mix of joins and relays is running.
* When the cap is full it waits for a slot (a condition variable notified whenever a slot is given back)
  instead of being refused, until the join's deadline (`join_timeout_seconds`, 180 s when unset).
* A server/key pair that recently failed is not fetched again, and a failure is remembered, through the
  same failure cache.
* It is not charged to a per-source rate. The source is this server's own join, and one join legitimately
  needs one key per server in the room.
* The join's fan-out is clamped to the cap as well, so it does not start tasks that would only wait.

### Positive Consequences

* Every network key resolution in the process is now bounded by the in-flight cap.
* Joins still verify every event they can.

### Negative Consequences

* Joining a large room is slower when its keys are not cached: 16 fetches at a time on main, not up to
  1024.
* While a large join runs, it holds slots that relay verification would otherwise get, so relays may see
  more 503 overload answers, which their senders retry.
* This is the one admission path that waits. A caller must not hold the federation mutex when it calls
  it, and a waiting join still holds a thread.
