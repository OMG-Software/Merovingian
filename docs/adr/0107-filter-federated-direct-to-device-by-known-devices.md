# Filter inbound federation direct-to-device EDUs by known local devices

* Status: accepted
* Date: 2026-10-05

Technical Story: security audit finding FED-3 continuation — an inbound `m.direct_to_device` EDU from a trusted remote server could probe whether arbitrary device IDs exist on this homeserver by observing whether a row was queued.

## Context and Problem Statement

The Matrix Server-Server API v1.19 says that `m.direct_to_device` messages are sent by the user's server and delivered to the target user's devices. Merovingian already rejects the whole EDU when the `sender` is not on the sending origin, deduplicates by `(origin, message_id)`, and skips target users that are not active local accounts. However, it was still enqueuing a per-device message for any device ID syntactically present under a valid local user, including device IDs that the user has never registered. This leaks whether a guessed device ID exists and creates sync-stream rows for undeliverable messages.

## Decision Drivers

* Do not leak account/device metadata to remote servers.
* Keep the EDU "best-effort" semantics: a single invalid target should not fail the whole transaction.
* Match the behavior already enforced for client-server `PUT /sendToDevice`.

## Considered Options

1. **Queue every per-device payload and let /sync discard unknown devices.** Simplest but leaks existence information through the `to_device_messages` table and wastes stream IDs.
2. **Reject the whole EDU if any device is unknown.** Fails closed but violates best-effort EDU semantics and allows a malicious sending server to intentionally fail delivery for a whole batch.
3. **Silently skip unknown devices while still queuing known ones.** Preserves best-effort delivery, avoids metadata leakage, and mirrors the client-server endpoint.

## Decision Outcome

Chosen option: "Silently skip unknown devices while still queuing known ones".

The inbound federation path now checks `runtime.database.persistent_store.devices` for a matching `(user_id, device_id)` before incrementing `targeted` or attempting to enqueue. Unknown devices are ignored; the rest of the EDU is processed normally. The transaction still returns 200 because EDUs are best-effort.

The device ID `*` is not a device to look up: the spec defines it as "all known devices for the user". It is expanded, when the EDU is received, into one queued row per device the target user has registered, exactly as the client-server `sendToDevice` path expands it (ADR-0105). Each expanded row counts as one delivery against the per-EDU delivery cap, so a wildcard cannot multiply past it. A user with no devices receives nothing.

Storing a single `*` row and fanning it out when each device syncs was rejected: the federated and local paths would then queue the same request differently; `drain_to_device_messages` never deletes a broadcast row, because no single device's acknowledgement covers it, so such rows would accumulate; and a device registered later, syncing from the start of its stream, would receive wildcard messages sent before it existed. An earlier revision of this decision matched `*` literally against registered devices, which silently dropped every wildcard message (for example `m.room_key_request` cancellations) while returning 200.

### Positive Consequences

* Remote servers cannot probe device existence through federation to-device.
* No sync stream rows are allocated for undeliverable guesses.
* Behaviour is consistent with the client-server `sendToDevice` path.

### Negative Consequences

* The sending server receives no signal that a device ID was invalid, so it cannot correct typos. This is acceptable because the spec treats to-device as best-effort and clients are expected to learn valid device IDs through room membership or key queries.

## Pros and Cons of the Options

### Queue every per-device payload

* Good, because the code change is minimal.
* Bad, because it leaks device existence and wastes stream IDs.

### Reject the whole EDU on any unknown device

* Good, because it is strictly fail-closed.
* Bad, because it breaks best-effort semantics and enables denial of delivery.

### Silently skip unknown devices

* Good, because it prevents metadata leakage without breaking other deliveries.
* Good, because it matches the client-server behaviour already under test.
* Bad, because invalid device IDs are not reported to the sender.

## Links

* Related to [ADR-0105 - Silently discard sendToDevice to unknown local recipients](0105-silently-discard-sendtodevice-to-unknown-local-recipients.md)
* Spec: docs/matrix-v1.19-spec/server-server-api.md "Send-to-device messaging"
