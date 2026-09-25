# Spec-conformant /state_ids fallback via /event_auth

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-09-22

## Context and Problem Statement

The ADR-0064 /state_ids fallback for backfilling missing prev_events was
security-hardened in items 2a-2c, but it still rarely succeeds in practice
because it verifies every snapshot state event through the normal
`/event/{id}` path, which requires each event's own prev_events to already
have recorded state groups. Historical state events deep in a room's chain do
not satisfy that requirement, so the fallback rejects the snapshot and leaves
the inbound PDU stuck in `missing_prev_state`. The 100-event cap on the
snapshot also causes real rooms to fail even when the snapshot is honest.

How should the /state_ids fallback be reimplemented so that it actually works
for honest rooms while remaining fail-closed against malicious origins?

## Decision Drivers

* Spec conformance: Matrix v1.19 defines `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...` and `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` precisely for this purpose.
* Security: a malicious origin must not be able to inject unverified state into the local room.
* Functionality: real rooms with long state chains must be able to backfill.
* Resource bounds: a single inbound PDU must not drive unbounded outbound work.

## Considered Options

* **Option A**: Reimplement the fallback as spec-conformant. Batch-fetch the
  auth chain for each snapshot state event via `/event_auth`, verify each
  claimed state event as an outlier without requiring its own prev_events to
  have state groups, use a separate bounded state-fetch budget, and raise or
  remove the 100-state-event cap.
* **Option B**: Keep the current prev_events-state-group requirement and
  simply raise the cap. Cheap, but leaves the fallback broken for the common
  case where historical prev_events have no state groups.
* **Option C**: Drop the /state_ids fallback entirely. Simpler and removes the
  attack surface, but causes backfill to fail for any gap that
  `/get_missing_events` cannot close, degrading federation reliability.

## Decision Outcome

Chosen option: "Option A", because it is the only option that both conforms
to the spec and allows real rooms to succeed. The alternative options trade
functionality for implementation simplicity, which is unacceptable for a
federation backfill path.

### Positive Consequences

* The /state_ids fallback now matches the Matrix v1.19 backfill flow.
* Honest rooms with historical state events whose prev_events are missing can
  be backfilled successfully.
* Snapshot state events are verified against their own auth chain (signature,
  hash, auth rules) before being used as state.
* A separate `state_fetch_calls` budget isolates state materialisation from
  the main backfill outbound-call budget, so one cannot starve the other.

### Negative Consequences

* Snapshot state events are verified against their auth chain rather than the
  full historical state before them. This is a deliberate relaxation: the
  spec's `/event_auth` endpoint is designed to supply exactly the events
  needed to authorize an event, and the origin already chooses the snapshot
  it returns. A malicious origin can still only supply events it can sign for
  the room.
* The implementation is more complex than Option B or C.

## Links

* Refines [ADR-0064 - Spec-conformant PDU ingestion with delta state groups](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
* Spec: `docs/matrix-v1.19-spec/server-server-api.md` — /state_ids and /event_auth endpoints
