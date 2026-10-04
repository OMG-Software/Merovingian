# Defer unsolicited PDUs during outbound joins in bounded transient queues

* Status: accepted
* Date: 2026-10-02

## Context and Problem Statement

The FED-11 audit found that validly signed PDUs for rooms with no local
participation were persisted indefinitely, including rejected events. Admission
must precede stream allocation, missing-history fetches, cache mutation, and
persistence; authorization rejection is not a storage bound.

A membership-only gate is insufficient for outbound joins. Their network
exchange runs without the runtime mutex, before verified initial state and local
membership have been committed, so legitimate concurrent PDUs can arrive before
ordinary room interest exists. Persisting them immediately would also retain
unwanted data after a failed join.

## Considered Options

* Admit every signed PDU and retain authorization failures.
* Admit only rooms with current local membership, dropping concurrent join PDUs.
* Permit immediate persistence while any outbound join is active.
* Defer concurrent join PDUs in bounded, transient, room-scoped queues.

## Decision Outcome

Chosen option: "Defer concurrent join PDUs in bounded, transient, room-scoped
queues", to preserve legitimate join traffic without making failed joins a
source of permanent unsolicited storage.

The common PDU sink first checks current local `join`, `invite`, or `knock`
interest. Remote-only, malformed, departed, and banned membership rows are not
admission signals. Room metadata and room-version resolution are not signals
either. Solicited join-state bootstrap and verified requested-backfill writers
remain explicit separate paths; PDU content cannot claim those privileges.

For a room without current local interest, only a locally established outbound
join lease permits deferral. The RAII lease is acquired under the runtime mutex
before the network exchange releases it. Refuse same-room overlap and limit
pending joins to 32 rooms. Each queue admits at most 32 distinct event IDs and
512 KiB of stored JSON. Excess is refused without database or watermark changes.
All queue accesses use the runtime mutex.

Discard queued PDUs on failure or exception. After verified initial state and
local membership are committed successfully, remove the transient reservation
and drain through the existing common sink. Release every global-lock recursion
level before draining, preserving the sink's stripe-then-global lock order.
Backlog-drain failures must not reinterpret an already committed join as a failed
join; the bounded transient remainder is discarded.

### Positive Consequences

* Unsolicited unknown-room transactions cannot create stored rejected events or
  advance stream counters.
* Failed joins do not convert transient PDU queues into permanent event rows.
* The direct and federation-worker relay paths share admission and normal
  post-join ingestion.
* Duplicate PDUs and repeated failed joins cannot grow the transient queues
  without bound.

### Negative Consequences

* Same-room concurrent joins and joins beyond the reservation cap are refused
  rather than queued for execution.
* Traffic beyond the transient queue limits, or remaining after a drain failure,
  is not retained by this buffer; this is bounded best-effort deferral, not a
  durable transaction queue.
* Future alternate join paths must establish and clean up the same room-scoped
  lease rather than bypass admission.

## Links

* [FED-11 audit finding](../security-audit-report-2026-09-29.md)
* [ADR-0009: per-room ingestion stripes](0009-serialize-inbound-pdu-ingestion-on-per-room-stripes.md)
* [ADR-0003: release every runtime-lock recursion level](0003-drain-every-recursion-level-in-one-release-primitive.md)
* [ADR-0064: spec-conformant PDU ingestion](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
