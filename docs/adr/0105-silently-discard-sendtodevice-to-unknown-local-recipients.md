# Silently discard sendToDevice to unknown local recipients

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-10-05

Technical Story: security audit finding on `fix/audit-medium-0.12.16`

## Context and Problem Statement

The client-server `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`
endpoint accepts a `messages` object mapping user IDs to device IDs to content.
The original implementation enqueued a `to_device_messages` row for every local
`(user_id, device_id)` pair that had the local server suffix, without checking
whether the user existed or whether the device belonged to that user. This had
two security consequences:

1. **Existence oracle:** an attacker could learn whether a given local user or
   device ID exists by observing whether the request "succeeded" in allocating
   state.
2. **State amplification:** any authenticated local user could create durable
   sync-queue state for arbitrary invented recipients, advancing the shared sync
   stream ID and growing the queue without owning a real device.

The Matrix v1.19 Client-Server API leaves the server's handling of unknown local
recipients undefined; a privacy-preserving policy is to silently discard them.

## Decision Drivers

* Do not disclose which local users or devices exist.
* Do not let a sender create durable to-device queue state for targets that do
  not own a real registered device.
* Preserve the spec-defined wildcard `*` fan-out to all of the target user's
  registered devices.
* Keep the endpoint idempotent and returning `200 {}` on success, as required by
  the spec.

## Considered Options

1. **Return an error for unknown recipients (e.g. `400` or `403`).** Would stop
   state amplification, but the response code or error details would reveal
   whether the user/device exists, creating an existence oracle.
2. **Silently discard unknown recipients, keeping the `200 {}` response.**
   Matches the server's existing privacy policy for remote EDU targets and
   avoids leaking existence information.
3. **Queue all deliveries but lazily skip unknown devices at sync time.** Would
   still advance the sync stream ID and allocate durable rows, failing the
   amplification goal.

## Decision Outcome

Chosen option: **option 2**. For each local recipient:

* If the target user does not exist locally, skip the delivery.
* If a non-wildcard device ID is named, skip unless that device is registered to
  the target user.
* If the wildcard device ID `*` is named, fan out only to the target user's
  registered devices and do not retain a `*` row.

Skipped deliveries do not call `push_to_device_message`, so they do not advance
`next_sync_stream_id` or create durable state. The endpoint still records the
client txn id so retries remain idempotent.

### Positive Consequences

* No existence oracle for local users or devices.
* No queue-state amplification from invented recipients.
* Wildcard fan-out remains spec-compliant and efficient.

### Negative Consequences

* A typo in a recipient device ID silently drops the message. This is consistent
  with the Matrix spec's general "fire-and-forget" semantics for to-device
  messaging and with the server's existing remote-EDU policy.
* A client that expects a partial-failure error code will not receive one.
  Synapse and other servers already return `200` for the same situation.

## Links

* `src/homeserver/client_server.cpp` — `handle_send_to_device`
* `tests/integration/test_security_audit_to_device_flow.cpp`
* Relates to ADR-0090 (Bound Argon2id work with a process-wide admission semaphore)
