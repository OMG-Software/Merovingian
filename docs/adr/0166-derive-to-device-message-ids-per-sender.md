# Derive to-device message IDs per sender and record them only after the messages commit

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-10-17

Technical Story: audit follow-up to R02, `fix/to-device-message-id`

## Context and Problem Statement

The `m.direct_to_device` EDU carries a `message_id` that the Matrix v1.19
Server-Server API describes as a "Unique ID for the message, used for idempotence.
Arbitrary utf8 string, of maximum length 32 codepoints." Two defects followed from
how this server filled it in and used it.

Outbound, the EDU's `message_id` was the raw client transaction ID. Client
transaction IDs are only unique per user, so two local users who both used `"1"`
sent two EDUs with the same `message_id` to one destination, and a receiver that
de-duplicates per origin (this server does) dropped the second as a replay. A
transaction ID longer than 32 codepoints produced an invalid `message_id`.

Inbound, `EduIdempotenceWindow::first_sighting` recorded `(origin, message_id)`
before the messages were stored, and every device's message was committed on its
own. If a commit failed the EDU was partly stored, its ID was already recorded, and
the origin's resend was dropped as a replay: messages were lost or only partly
delivered, with the origin told the EDU had been handled.

## Decision Drivers

* A client retry of one `sendToDevice` request must carry the same `message_id`, so
  the receiver treats it as a replay.
* Two different senders must never share a `message_id`.
* The ID must always satisfy the spec's 1 to 32 codepoint rule.
* A resend of an EDU that failed to store must be processed in full.
* No migration: the replay window stays in memory.

## Considered Options

* Derive the ID: a hash of (sender, event type, txn id), length-prefixed, truncated
  and URL-safe base64 encoded
* Use the raw client transaction ID
* Use a random ID per send
* Keep recording the ID before the messages are stored

## Decision Outcome

Chosen option: "derive the ID, and record it only after the commit".

* Outbound, `federation::derive_direct_to_device_message_id(sender, event_type,
  txn_id)` hashes a fixed domain string and the three inputs, each prefixed with its
  length (the hash helper separates pieces with a NUL, which a percent-encoded
  transaction ID can contain), with `crypto::generic_hash_bytes`. The first 18 bytes
  are encoded with `crypto::base64_urlsafe_encode`: 24 characters, no padding. A
  hashing failure answers `500 M_UNKNOWN` before anything is queued.
* Inbound, the replay window is keyed on `(origin, sender, message_id)` and split
  into a non-mutating `seen` and a `record`. `enqueue_direct_to_device_messages`
  holds `runtime.mutex` across check, store and record, builds every message first,
  commits them all in one backend transaction (`database::enqueue_to_device_messages`),
  and records the ID only after that commit succeeds. A failed commit stores nothing
  and leaves the ID unrecorded, and the existing `store_incomplete` disposition is
  kept.

### Positive Consequences

* Senders cannot suppress each other's EDUs, and every outbound ID is spec-valid.
* A retry of one request is still recognised as a replay by the receiver.
* An inbound EDU is stored all-or-nothing, so a resend after a failure delivers every
  device's message exactly once.

### Negative Consequences

* The `message_id` on the wire is opaque: it can no longer be read back as the
  client's transaction ID when debugging.
* The window is still in memory, so a replay that straddles a restart is delivered
  again (unchanged, and deliberate).

## Pros and Cons of the Options

### Raw client transaction ID

* Good, because it is trivial and stable across a retry.
* Bad, because client transaction IDs are unique only per user, so two senders collide
  and the receiver drops one EDU as a replay.
* Bad, because it may exceed 32 codepoints, which the spec forbids.

### Random ID per send

* Good, because it is unique across senders and always valid.
* Bad, because a client retry that re-sends the EDU gets a new ID, so the receiver
  cannot recognise it as a replay and delivers the message twice.

### Record the ID before the messages are stored

* Good, because it is one step simpler, and a concurrent duplicate cannot slip through.
* Bad, because a failed store leaves the ID recorded, and the origin's resend is then
  dropped as a replay: the messages, possibly E2EE room keys, are lost. Holding the
  runtime mutex across check, store and record gives the same exclusion without that
  failure.

## Links

* Refines [ADR-0164](0164-send-to-device-commits-its-local-messages-and-txn-id-together.md)
