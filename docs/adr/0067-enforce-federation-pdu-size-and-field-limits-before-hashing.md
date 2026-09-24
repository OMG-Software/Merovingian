# Enforce federation PDU size and field-count limits before hashing

* Status: accepted
* Date: 2026-09-24

## Context and Problem Statement

The 0.12.13 security audit (finding M3) found that the inbound federation path
accepted PDUs with no enforced size or field-count limits. Matrix spec v1.19
"Size limits" requires a room event to be no larger than 65 536 bytes of
canonical JSON (with federation event format), limits `sender`, `room_id`,
`state_key`, and `type` to 255 bytes each, and caps `prev_events` at 20 and
`auth_events` at 10 for every room version. Without these bounds an attacker
could push arbitrarily large or wide events through `/send`, wasting memory,
CPU, and storage before the more expensive hash, signature, and authorization
steps ever ran.

## Decision Drivers

* Conformance to Matrix v1.19 is non-negotiable (`docs/AGENTS.md` and
  `CLAUDE.md` name the spec as the authority).
* Rejection must be cheap: an oversized or over-counted PDU should not reach
  JSON parsing, canonical serialization, SHA-256 hashing, or Ed25519
  verification.
* The same numeric constants must govern both the inbound federation envelope
  and the general event-envelope parser so local and remote events are judged
  identically.

## Considered Options

1. **Enforce limits before parsing/hashing.** Check raw PDU byte size, array
   counts, and identifier/state-key lengths early in
   `parse_inbound_pdu_envelope` and `parse_event_envelope`.
2. **Enforce after parsing but before authorization/storage.** Parse the PDU
   into a `Value`, then inspect size and counts before persisting.
3. **Leave it to downstream authorization.** Rely on auth rules and the store
   to implicitly reject anything "too big".

## Decision Outcome

Chosen option: **enforce limits before parsing/hashing**, because it satisfies
spec conformance at the lowest possible cost and fails closed against DoS.

`include/merovingian/events/limits.hpp` now exposes
`max_event_size_bytes` (65 536), `max_id_length_bytes` (255),
`max_state_key_length_bytes` (255), `max_prev_events_per_event` (20), and
`max_auth_events_per_event` (10). `parse_inbound_pdu_envelope` rejects any
PDU whose raw JSON exceeds `max_event_size_bytes` before yyjson touches it, and
rejects `prev_events`/`auth_events` arrays larger than their caps immediately
after extracting them. `parse_event_envelope` rejects a `state_key` longer than
255 bytes before hashing, and `matrix_id_is_valid` rejects any identifier
longer than 255 bytes.

### Positive Consequences

* CPU and memory spent on a non-conformant PDU is bounded to a trivial
  size/length check.
* Fail-closed behaviour matches the rest of the ingestion pipeline: a
  non-conformant PDU returns `std::nullopt` and is never stored.
* One set of constants is shared by event parsing and federation ingestion,
  avoiding divergent local and remote behaviour.

### Negative Consequences

* A 65 536-byte PDU is still parsed and authorized; the cap is generous and
  chosen by the spec, not by us.
* Very long but under-limit identifiers are still hashed; the 255-byte cap
  prevents abuse while remaining spec-compliant.

## Pros and Cons of the Options

### Enforce limits before parsing/hashing

* Good, because it rejects DoS input at the cheapest possible point.
* Good, because it keeps the spec caps in one header and applies them
  consistently.
* Bad, because it adds an early gate that must be maintained as the spec
  evolves, but the limits are stable across room versions.

### Enforce after parsing but before authorization/storage

* Good, because the same parsed structure can be reused for the limit check.
* Bad, because an oversized PDU still pays for JSON parsing, canonical
  serialization, and content hashing — exactly the work the attacker wants to
  force.
* Bad, because memory usage is already unbounded before the check fires.

### Leave it to downstream authorization

* Good, because it requires no new code.
* Bad, because nothing in the auth rules enforces the spec size or array-count
  limits, so non-conformant events would be accepted and persisted.

## Links

* Matrix v1.19 "Size limits" (referenced in `docs/matrix-v1.19-spec/index.md`
  and the server-server API room-event format sections).
* `include/merovingian/events/limits.hpp` — the shared constants.
* `src/federation/inbound_ingestion.cpp` — inbound PDU limit checks.
* `src/events/event.cpp` — event-envelope and identifier length checks.
* `docs/event-engine.md` — event-engine capability note.
* `CHANGELOG.md` 0.12.13 — M-03 entry.
