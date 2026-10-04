# Bound conflicted state traversal by distinct auth events

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Audit EVT-9 found that enumerating paths through a shared auth DAG repeatedly
consumed the visit budget for the same events. EVT-5 found that mainline ordering
stopped when an ancestor was outside the submitted state.

## Considered Options

* Memoize the reachable graph and compute reverse reachability.
* Increase the recursive path-enumeration budget.
* Stop at the first conflicted endpoint.

## Decision Outcome

Build the reachable auth DAG once, enforcing the existing distinct-event and
per-event auth-reference caps. Reject incomplete, malformed or cyclic graphs.
Reverse-walk from conflicted endpoints: the desired subgraph is the intersection
of vertices reachable from an endpoint with those able to reach an endpoint.
Preserve endpoints. Work scales with vertices and edges, not path count.

Increasing the budget merely moves an exponential threshold. Stopping at an
endpoint omits longer paths to other endpoints. Required mainline ancestors use
the shared event source, including external lookup; incomplete ordering fails
closed rather than falling back to timestamps.

### Positive Consequences

* Shared paths cannot exhaust a budget by revisiting vertices.
* Missing data cannot silently choose a different event ordering.

### Negative Consequences

* Oversized or incomplete inputs still fail closed.

## Links

* [Room v12](../matrix-v1.19-spec/rooms/v12.md#state-resolution)
* [Room v10 mainline ordering](../matrix-v1.19-spec/rooms/v10.md#mainline-ordering)
