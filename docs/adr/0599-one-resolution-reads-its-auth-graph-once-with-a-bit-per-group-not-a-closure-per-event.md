# One resolution reads its auth graph once, with a bit per group, not a closure per event

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `F-resource-exhaustion.events.state-resolution-auth-chain-recomputation`. Refines
[ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md).

## Context and Problem Statement

`resolve_state_v2` walked the auth chain of every event in every state group from scratch, again for every power event
while enlarging X, and walked power-level ancestors again for every event it placed on the mainline. A room whose K state
events cite one chain of D events cost K x D reads, with `runtime.mutex` held, and both K and D are chosen by whoever
writes the events. The distinct-event caps bound D and K separately, so the product stayed open.

The result must not change: this is memoisation of a pure function, and the same inputs must be refused for the same
reasons.

## Decision Drivers

* Work under the lock must not grow with the product of two things a remote server chooses.
* Memory must not grow that way either.
* `max_auth_chain_walk_events` limits one group's chain, and `max_mainline_auth_chain_depth` limits one walk's hops. Those
  meanings, and what they refuse, stay.
* A chain can be 131072 events deep, so nothing may recurse along it.

## Considered Options

* Memoise each event's transitive closure as a set, as the finding proposed.
* Read the graph once, then walk it per group.
* Read the graph once, keep one bit per group on each event, and push the bits from dependants to ancestors.

## Decision Outcome

Chosen option: "Read the graph once, keep one bit per group on each event", because it removes the product from both time
and memory.

`AuthChainGraph`, local to `StateResolution.cpp`, turns each reachable event into a small integer the first time it is seen
and reads its `auth_events` once. `compute_auth_difference` then sets a bit for group i on every event a state event of
group i cites, and carries the bits to ancestors in one pass in reverse finishing order. An event with some bits but not all
is in the auth difference. The cost is (events + edges) x groups / 64, and `max_state_groups` bounds the last term.

A group's size is the number of events holding its bit, so the refusal for more than `max_auth_chain_walk_events` is exact.

Enlarging X is one traversal from every power event at once. Each power event's chain is part of some group's chain, so it
needs no cap of its own.

The mainline position of each off-mainline power-levels event is remembered with the number of reads a walk from it takes.
A later walk that reaches it adds that number to its own, so a walk that would have exceeded the depth limit by hops is
refused even when most of its hops were remembered.

`StateResolutionResult::auth_walk_visits` counts the reads, for tests that prove the bound by work, never by time.

### Positive Consequences

* One resolution reads each distinct event a constant number of times, however many state events cite it.

### Negative Consequences

* Transient memory of `groups / 8` bytes per event reached: at most about 33 MB at the default caps.

## Pros and Cons of the Options

### Memoise each event's transitive closure as a set

* Good, because it is the obvious memoisation, and a union of cached sets looks simple.
* Bad, because a chain of D events holds D sets of average size D/2: O(D²) memory. At the default cap that is about 8.6
  billion entries, so it trades a time attack for a memory one.

### Read the graph once, then walk it per group

* Good, because it is simple and has no bit arithmetic.
* Bad, because it still costs events x groups, 64 times the chosen option's cost, for each of up to 1000 groups.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
