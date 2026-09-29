# Bound the connection queue but not the IPC queue

* Status: superseded by ADR-0065 for the IPC pools only; the connection-queue half remains accepted
* Date: 2026-09-06

## Context and Problem Statement

Both HTTP accept loops queued one closure per accepted connection into an
unbounded `std::queue`, so a connection flood grew it until the OOM reaper
fired. The same `ThreadPool` type also backs the federation worker's IPC
dispatch pools.

Bounding a queue means dropping work when it is full. What gets dropped
matters.

## Considered Options

* Bound the network-facing queue only, leaving the IPC pools unbounded
* Bound both queues uniformly

## Decision Outcome

Chosen option: "Bound the network-facing queue only". `submit()` refuses past
`listeners.max_queued_connections` (default 1024) and the listener closes the
refused connection.

**The IPC dispatch pools deliberately keep the unbounded default**, because
their producer is the local supervisor, not a remote peer. Dropping there would
silently lose federation work rather than shed a connection — a refused
connection is a client retry; a dropped IPC message is a lost PDU.

### Negative Consequences

* Two pools of the same type now have different queue semantics, which is
  surprising unless the producer asymmetry is known. That asymmetry is the
  whole decision.
* The IPC path's safety depends on the supervisor remaining a trusted,
  self-limiting producer. If it ever became driven by remote input, this
  reasoning collapses.

## Links

* `CHANGELOG.md`, 0.12.5 (audit findings 11-13, 19)

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
