# src/events/ — Events Module

Implements Matrix event parsing, signing, hashing, authorization, state resolution, and redaction.
Spec authority: https://spec.matrix.org/v1.18/server-server-api/

## Key files and their responsibilities

| File | Responsibility |
|---|---|
| `event.cpp` | Parse raw JSON into `EventEnvelope`; validate field types and required keys |
| `event_id.cpp` | Generate and validate event IDs (format is room-version-dependent) |
| `event_signer.cpp` | Compute content hash, reference hash, and apply Ed25519 signature |
| `authorization.cpp` | Authorization rules — room-version-aware; called before persisting any PDU |
| `state_resolution.cpp` | State resolution v2 algorithm — do not inline resolution elsewhere |
| `redaction.cpp` | Strip non-essential keys per room-version redaction algorithm |

## Event IDs are room-version dependent

| Room version | Event ID format |
|---|---|
| v1–v2 | `$localpart:server` |
| v3+ | `$` + unpadded base64url(SHA-256(reference hash of redacted event)) |

Always use `event_id.hpp` — never construct an event ID manually.

## Canonical JSON is required for signing and hashing

All signing and hashing operates on canonical JSON output from `canonicaljson/serializer.hpp`.
Never sign or hash a string that was not produced by the canonical serializer.

## Signing pipeline

```
EventEnvelope → redact → canonical JSON → SHA-256 (content hash) → inject "hashes"
              → redact → canonical JSON → SHA-256 (reference hash) → derive event ID
              → add "signatures" field via signing_service
```

Call `event_signer.hpp` — do not call `crypto/signing_service.hpp` directly.

## Authorization rules

`authorization.hpp` is room-version-aware. Always pass the correct `RoomVersionPolicy`
(from `rooms/room_version_policy.hpp`). Do not assume v10 rules apply to all room versions.

Authorization must be checked:
1. Before persisting any locally-created event
2. Before accepting any inbound PDU from federation

## State resolution

`state_resolution.hpp` implements the v2 algorithm.
Never inline resolution logic; always delegate to this module.

## Redaction

`redaction.hpp` applies the room-version-specific redaction algorithm.
Do not trim event fields manually — the algorithm determines what survives.

## Key spec sections

- [PDU format](https://spec.matrix.org/v1.18/server-server-api/#pdus)
- [Content hash](https://spec.matrix.org/v1.18/server-server-api/#calculating-the-content-hash-for-an-event)
- [Reference hash](https://spec.matrix.org/v1.18/server-server-api/#calculating-the-reference-hash-for-an-event)
- [Event signing](https://spec.matrix.org/v1.18/server-server-api/#signing-events)
- [Authorization rules](https://spec.matrix.org/v1.18/server-server-api/#authorization-rules)
- [State resolution](https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution)
- [Redactions](https://spec.matrix.org/v1.18/server-server-api/#redactions)
