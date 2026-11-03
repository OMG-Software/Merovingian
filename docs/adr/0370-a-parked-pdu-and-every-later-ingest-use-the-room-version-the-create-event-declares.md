# A parked PDU and every later ingest use the room version the create event declares

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-44. Refines ADR-0089 (the queue) and ADR-0179 (one accessor for a room's version).

## Context and Problem Statement

While a local user's federated join is in progress, PDUs for the room are parked (ADR-0089). No create event is stored
yet, so every receipt path guesses version 12: the event ID, the signature check and `InboundPduEnvelope::room_version`
all follow the guess. The drain replayed those envelopes unchanged, and `ingest_pdu_event` took its policy from the
envelope. A creator of a pre-v12 room could therefore have an event judged by the version 12 rules, where a creator
outranks everyone and `auth_events` omit the create event, and honest events naming the create were refused.

## Considered Options

* Re-verify and rebuild each parked PDU under the stored version, and make ingestion refuse an envelope that disagrees
* Only make ingestion refuse an envelope that disagrees
* Only make ingestion take its policy from the stored create, keeping the envelope's event ID
* Refuse to park anything until the room version is known

## Decision Outcome

Chosen: re-verify and refuse. The drain runs each PDU through `filter_verified_send_join_events` under the version the
stored create declares and rebuilds the envelope, which also recomputes the event ID, with `runtime.mutex` released.
`ingest_pdu_event` takes its policy from `stored_room_version` whenever a create is stored, and answers
`rejected_invalid` to an envelope naming another version.

The queue holds each PDU as received, not its redacted form: a redaction made under the guess may have removed what the
real version signs.

A parked PDU whose event ID differs under the real version is not dropped. The ID is derived from the event, so the
recomputed one is the true one, and version 3's different ID encoding would otherwise lose every honest event.

### Positive Consequences

* An honest event parked during a join is accepted under the room's real rules. It used to be refused.
* No path can apply one room's rules to a PDU verified under another's.

### Negative Consequences

* A PDU that is in flight when the join commits, parsed before the create was stored and ingested after, is refused. The
  sender's transaction reports the error for that event, and it can be recovered by the ordinary gap fill.
* Each parked PDU is verified a second time. The queue is bounded (`pending_join_max_pdus`, `pending_join_max_bytes`), and
  the keys are normally already cached.

## Pros and Cons of the Options

### Only make ingestion refuse an envelope that disagrees

The drain's envelopes all carry the guess, so every parked PDU in a pre-v12 room would be refused.

### Only make ingestion take its policy from the stored create

Would judge the event by the right rules under an event ID and signatures verified by the wrong ones.

### Refuse to park anything until the room version is known

ADR-0089 parks PDUs so that events sent while a join completes are not lost. The make_join answer's version is not proof
either: only the verified create is.
