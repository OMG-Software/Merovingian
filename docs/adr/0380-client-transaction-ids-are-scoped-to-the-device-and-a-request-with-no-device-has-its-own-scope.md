# Client transaction IDs are scoped to the device, and a request with no device has a scope of its own

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-52

## Context and Problem Statement

The spec scopes a client transaction ID to one device and one HTTP endpoint, and says a re-login that creates a new device
makes a reused ID a distinct request (client-server-api.md, "Transaction identifiers"). The server recorded and looked up
`PUT /send`, `PUT /redact` and `PUT /sendToDevice` transactions by user, room, event type or scope, and transaction ID. A bot
that logged in afresh and restarted its counter, or two clients of one account, had the second device's request answered with
the first device's `event_id` (or `{}`) and nothing created or delivered. ADR-0258 listed "Idempotency is still keyed by user,
not device" as a known consequence. ADR-0166 derived the federation `message_id` of a to-device send from sender, event type
and transaction ID, so two devices of one user with the same ID would also have shared a `message_id`, and a receiving
server would have dropped the second as a replay.

What decides the scope of a request that has no device? An appservice token that names no device has an empty device ID.

## Considered Options

* Add the device to the idempotency key, the table's primary key and the federation `message_id`; an empty device ID is a scope of its own
* The same, but refuse a request with no device
* Keep the key per user and document it

## Decision Outcome

Chosen option: "add the device to the key, and let an empty device ID be a scope of its own", because the spec requires the
scope and a deterministic empty scope keeps appservice requests working.

* The key is `(user_id, device_id, room_id, event_type, txn_id)`: `client_txn_key`, the match in `find_client_txn_event_id`,
  `store_client_txn`, `enqueue_to_device_messages_with_client_txn` and the `client_txn_ids` primary key. All three endpoints take
  the device from `authenticated_request_device_id`; `sendToDevice` records it too (it recorded an empty one).
* `derive_direct_to_device_message_id(sender, sender_device, event_type, txn_id)` hashes the device as one more length-prefixed
  piece, so two devices that reuse an ID send distinct `message_id`s. A retry from one device still derives the same one.
* A token refresh keeps the device ID, so it stays one scope; a re-login that creates a new device is a new scope. An
  appservice's masquerade token carries the device its identity names, or none: with none the empty string is the scope, so all
  of that user's no-device requests share one scope, deterministically.

### Positive Consequences

* A second device's send, redaction or to-device delivery is no longer dropped behind a false 200.
* The device is stored on every row already, so `unsigned.transaction_id` (ADR-0258) is unchanged.

### Negative Consequences

* A client that resends one request from a different device now sends it twice. That is what the spec says.
* The `message_id` on the wire changes for every to-device EDU, so a retry that straddles the upgrade is delivered again.

## Pros and Cons of the Options

### Refuse a request with no device

* Good, because every scope would be a real device.
* Bad, because it breaks appservices that send as a user without naming a device.

### Keep the key per user

* Good, because it needs no change.
* Bad, because it loses messages and key shares, and contradicts the spec.

## Links

* Supersedes the negative consequence "Idempotency is still keyed by user, not device" of [ADR-0258](0258-unsigned-transaction-id-goes-to-the-sending-device.md)
* Refines [ADR-0166](0166-derive-to-device-message-ids-per-sender.md): the derived `message_id` is per sender device
