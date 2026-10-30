# A former member never sees events that descend from their leave

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: PR #546 review

## Context and Problem Statement

ADR-0308 judges the `shared` rule ("the user joined the room at any point after the event was sent") by
depth: the user's newest join must be deeper than the event. Depth is a number in the event, chosen by
whoever creates it and not checked against its `prev_events` on receipt, and a federated join's depth comes
from the resident's `make_join` template. A hostile server could therefore show a user who left events sent
after they left: by giving its own post-leave events a low depth, or, as the resident of their join, by giving
the join a huge one, which reveals post-leave events from every server.

## Considered Options

* Keep depth, and for a user who left hide an event that descends from their leave (a bounded walk)
* Compute a local depth from held predecessors instead of trusting the claimed one
* Accept the risk and document it

## Decision Outcome

Chosen option: "hide an event that descends from their leave" (owner decision 2026-10-30). For a user whose
current membership is `leave` or `ban`, an event the depth rule would allow is walked back through its held
`prev_events`. Nothing stored before the leave can descend from it, so the walk stops at such events and at
events not held, which keeps it short; it hides the event if it reaches the leave, and fails closed (hides)
past 500 events. When the leave event is not held (a federated leave keeps only the membership row), an
event stored after the leave that only the depth rule allows is hidden. Local depth was rejected: right after
a federated join this server holds none of the join's predecessors, so the join keeps the resident's depth,
and capping it compresses the room's scale until fetched pre-join history is hidden again (ADR-0308).

### Positive Consequences

* No choice of depths by another server shows a former member anything built on their leave.

### Negative Consequences

* A former member whose leave event is not held does not see history fetched after they left.
* A walk can cost up to 500 lookups for an event a former member asks about after leaving.

## Links

* Refines [ADR-0308](0308-shared-history-visibility-orders-the-join-and-the-event-by-depth.md)
