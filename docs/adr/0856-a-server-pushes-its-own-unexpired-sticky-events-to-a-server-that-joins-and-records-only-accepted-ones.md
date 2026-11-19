# A server pushes its own unexpired sticky events to a server that joins, and records only accepted ones

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4354 adds no federation endpoint. A sticky event travels as an ordinary PDU in `/send`. A server MUST push its own
unexpired sticky events to every server in the room, including a server that joins later, and MUST NOT drop them from a
full send queue. It does not relay other servers' sticky events. What does this server send, and what does it accept?

## Decision Outcome

**Outbound.** A locally composed sticky event goes out through `queue_event_to_room_servers`, like every local event.
When a remote server joins a room (the places that already send that server our device lists), this server also queues
to that server alone every unexpired sticky event in the room whose sender is local. They go oldest first, as the
stored PDUs, unchanged. Another server's sticky events are never relayed.

**Inbound.** Sticky detection runs in the main process, in `ingest_pdu_event_locked`, after the event is accepted and
persisted. The federation worker does not decide it and adds no field to the PDU relay envelope. The received time is
the main process's clock at that point. A rejected, soft-failed or outlier event gets no sticky row
([ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)). The
per-sender cap applies to remote senders too.

**Known gaps, kept in `docs/todos/capability-gaps.md`:**

* The outbound dispatch queue is in memory and bounded. Under overload, or for a failing destination, it can give up a
  transaction, and a sticky event in it is not sent again until that destination joins again. MSC4354 wants a durable
  per-destination backlog that is never dropped; that is a separate change.
* A soft-failed sticky event is not re-evaluated when the room's state changes.

## Consequences

* A server that joins a room in the middle of a call learns of this server's call members at once, instead of after
  their next membership refresh, which can be up to an hour later.
* The relay envelope between the worker and main is unchanged.

## Links

* Related: [ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md)
* Related: [ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)
* Related: [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
