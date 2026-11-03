# Resolving the state before an event on a read path has its own budget, and a refusal is a 404

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-26 (one origin must not occupy the federation worker's `local_pool` with
cheap GETs)

## Context and Problem Statement

The state before an event with several `prev_events` is the resolution of their states (ADR-0363), the same
`homeserver::compute_state_before` call ingestion makes. Ingestion runs it under the operator's
`federation.state_resolution` limits, and under the room's stripe. A read path has neither the operator's config in
the worker's `build_state_*` signature, nor a right to take the room's write path's time: it runs on a worker
thread of `local_pool` (default 4 per shard) without `runtime.mutex`, for a remote server that is not trusted.

Which work may a read do, and what does it answer when the work is more than that?

## Considered Options

* Resolve under `StateResolutionLimits` with the auth-chain walk lowered to 10000 events
  (`max_event_auth_chain_events`), and answer 404 when resolution fails or runs out of budget.
* Resolve under ingestion's limits.
* Answer 404 for every event with several `prev_events`.
* Resolve only the keys the groups disagree on.

## Decision Outcome

Chosen option: the lowered walk, and 404. The other caps of `StateResolutionLimits` (groups, entries per group,
conflicted keys, mainline depth, total state events) stay at their defaults: they bound the work by the size of the
state, which is the size of the answer, and not by the room's history. The auth walk is the one limit that follows
auth events across the whole room, so it is the one a read lowers. `/state` and `/state_ids` use it for the state
before a STATE event with several `prev_events`; a message or other non-state event with several `prev_events`
needs no resolution because its recorded state is already the state before it (ADR-0363), and a state event with one
`prev_event` reads that event's group.

404 is the answer the spec gives for "the server doesn't know about the state at that event to return anything
useful", so a refusal needs no new status and a receiver already handles it. It is not `too_large`: the state is not
too big to send, this server declines to work it out here.

Ingestion's limits were rejected because the same state resolution would then run twice for every event that a
peer asks about, once with a budget the operator sized for one write and once per GET. Answering 404 for every merge
was rejected because a peer catching up asks for exactly the merge events of a forked room, and could not make
progress. Resolving only the disagreeing keys was rejected as a second resolver to keep in step with the first.

### Negative Consequences

* A merge of forks whose conflicting auth history is longer than 10000 events cannot be asked for over
  `/state` or `/state_ids`; the asker uses `/event`, `/get_missing_events` or `/backfill`.
* The resolution happens on each such GET; it is not cached. Its cost is bounded as above.

### Concurrency

The functions hold no state of their own (no `static`, no cache) and return owned data, never views into the store,
so a caller may put a lock around the provider without the answer outliving it. No lock is taken here, and none is
taken under `runtime.mutex`: the `/context` path reads only the event's own group.

## Links

* [ADR-0363](0363-state-at-an-event-is-read-from-the-recorded-state-groups.md)
* [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md),
  [ADR-0063](0063-fail-closed-on-unreachable-state-res-auth-chain-events.md)
