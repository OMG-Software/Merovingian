# Current state is resolved over all tips, never incrementally

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit,
`F-resource-exhaustion.state-resolution.every-accepted-pdu-resolves-all-distinct-extremity-states-under-runtime-mutex`.
Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md).

## Context and Problem Statement

A state event that adds one distinct state group makes the server resolve every distinct group again, under `runtime.mutex`.
The obvious saving is to fold the one changed group into the previous result: `resolve(previous_result, new_group)`.

## Decision Drivers

* Every server must reach the same state from the same events. A result that depends on the order this server received
  them forks the room.
* The results of state resolution must not change.

## Considered Options

* Fold each new group into the previous result.
* Resolve all distinct groups each time the set changes.

## Decision Outcome

Chosen option: "Resolve all distinct groups each time the set changes", because state resolution is not associative.

The algorithm's input is the whole set. The conflicted set, the auth difference across all groups, the reverse topological
power ordering and the mainline are all computed from every group at once. `resolve(resolve(A, B), C)` is not in general
`resolve(A, B, C)`: resolving A and B discards the losing events, so they cannot appear in the conflicted set or the auth
difference that C would have produced, and a power event that decides the three-way case is simply absent from the two-way
result. Folding would make current state depend on arrival order, which a remote server chooses.

The cost is bounded instead by resolving rarely and cheaply: one auth graph read per resolution (ADR-0599), a memo for an
unchanged set (ADR-0600), and a per-server limit on tips (ADR-0602).

### Positive Consequences

* Current state stays the function of the tips that the spec defines.

### Negative Consequences

* A state event that changes the set of groups costs a full resolution.

## Pros and Cons of the Options

### Fold each new group into the previous result

* Good, because a state event would cost one small resolution, however many tips stand.
* Bad, because it gives a different answer from the spec's algorithm, depending on the order events arrive.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
* Relates to [ADR-0599](0599-one-resolution-reads-its-auth-graph-once-with-a-bit-per-group-not-a-closure-per-event.md)
* Relates to [ADR-0600](0600-a-room-remembers-its-last-resolved-state-by-its-distinct-state-groups.md)
* Relates to [ADR-0602](0602-a-server-is-limited-to-its-own-share-of-a-rooms-forward-extremities.md)
