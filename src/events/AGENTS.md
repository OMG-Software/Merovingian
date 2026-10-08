# src/events/ — Events Module

Implements Matrix event parsing, signing, hashing, authorization, state resolution, and redaction.
Spec authority: ../../docs/matrix-v1.19-spec/server-server-api.md

## Key files and their responsibilities

| File | Responsibility |
|---|---|
| `event.cpp` | Parse raw JSON into `EventEnvelope`; validate field types and required keys |
| `event_id.cpp` | Generate and validate event IDs (format is room-version-dependent) |
| `event_signer.cpp` | Compute content hash, reference hash, and apply Ed25519 signature |
| `authorization.cpp` | Authorization rules — room-version-aware; called before persisting any PDU |
| `state_resolution.cpp` | State resolution v2 algorithm — do not inline resolution elsewhere |
| `redaction.cpp` | Strip non-essential keys per room-version redaction algorithm |
| `redaction_validity.cpp` | Where a room version keeps `redacts`, and whether a redaction applies to its target ("Handling redactions") |

## Event IDs are room-version dependent

| Room version | Event ID format |
|---|---|
| v1–v2 | `$localpart:server` (not supported, ADR-0076) |
| v3 | `$` + unpadded standard base64 of the reference hash (`+`, `/`) |
| v4+ | `$` + unpadded URL-safe base64 of the reference hash (`-`, `_`) |

Always use `event_id.hpp` — never construct an event ID manually.

`event_id.hpp` implements only the reference-hash format (`make_reference_hash_event_id()`,
`EventIdFormat::reference_hash`). Room versions 1 and 2, whose `$localpart:server` format this
is, are not supported and are absent from `rooms/room_version_policy.cpp` (ADR-0076).

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

`state_resolution.hpp` implements state-res v2 (room versions 2-11) and v2.1
(room v12, `rooms::StateResolutionAlgorithm::v2_1` — empty starting map for
the iterative auth checks, plus the conflicted state subgraph). Never inline
resolution logic; always delegate to this module.

`StateResolutionRequest::event_lookup` lets the resolver fetch events beyond
the submitted state groups, to walk `auth_events` chains for the auth
difference (rooms/v10.md — Definitions) and the v12 conflicted state
subgraph (rooms/v12.md — Definitions). This walk is reachable from untrusted
federation input, so it is bounded (`events::max_auth_chain_walk_events`) and
**fails closed**: a missing or unreachable auth-chain event, or exceeding the
cap, returns an unresolved result rather than resolving on a partial chain.
The iterative auth checks' own separate fallback (using an event's own
`auth_events` when the running state lacks a required key, per the spec's
"Iterative auth checks" definition) uses a soft lookup instead — an
unreachable ancestor there only fails that one event's own auth check, not
the whole resolution, matching its behaviour before the fallback existed.

## Redaction

`redaction.hpp` applies the room-version-specific redaction algorithm.
Do not trim event fields manually — the algorithm determines what survives.

`redaction_validity.hpp` decides whether a redaction applies: `redaction_target` reads `redacts` from the
location the room version uses (top level before v11, `content` from v11), and `judge_redaction` applies the
two conditions of "Handling redactions" (sender's power level at least the redact level, or the sender's
domain equals the original sender's). Callers pass the power levels from the redaction's own `auth_events`, not
the room's current state, so every server reaches the same verdict. It never applies a redaction of
`m.room.create`: the server reads the room version from that event and, before v11, the algorithm strips it.
Applying a redaction is `homeserver/redaction_service.cpp`, not this module.

## Key spec sections

- [PDU format](../../docs/matrix-v1.19-spec/server-server-api.md#pdus)
- [Content hash](../../docs/matrix-v1.19-spec/server-server-api.md#calculating-the-content-hash-for-an-event)
- [Reference hash](../../docs/matrix-v1.19-spec/server-server-api.md#calculating-the-reference-hash-for-an-event)
- [Event signing](../../docs/matrix-v1.19-spec/server-server-api.md#signing-events)
- [Authorisation rules](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules)
- [State resolution](../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution)
- [Redactions](../../docs/matrix-v1.19-spec/client-server-api.md#redactions)
