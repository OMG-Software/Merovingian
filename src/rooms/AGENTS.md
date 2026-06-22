# src/rooms/ — Rooms Module

Room creation, membership, power levels, and room version policy enforcement.
Spec authority: ../../docs/matrix-v1.18-spec/client-server-api.md#rooms

## Key files

| File | Responsibility |
|---|---|
| `room_version_policy.cpp` | Maps room version strings to their policy (auth rules, event format, state resolution algorithm) |
| `encryption_policy.cpp` | Enforces `m.room.encryption` state; tracks per-room encryption requirement |

## Room version policy

`RoomVersionPolicy` is the authoritative source of which rules apply to a given room.
Always obtain a `RoomVersionPolicy` from `room_version_policy.hpp` before:
- Evaluating authorization rules (`events/authorization.hpp`)
- Running state resolution (`events/state_resolution.hpp`)
- Constructing event IDs (`events/event_id.hpp`)
- Applying redaction (`events/redaction.hpp`)

Do not hard-code version-specific logic outside this module.

## Supported room versions

Support for v1–v12 per Matrix spec v1.18. Room v12 adds `via` servers for join routing (MSC4291).
See `docs/matrix-v1.18-spec/rooms/index.md` for the feature matrix.

## Encryption policy

Rooms with `m.room.encryption` state require all messages to be encrypted.
`encryption_policy.hpp` tracks this per room and is consulted before accepting a plaintext
`m.room.message` event.

## Key spec sections

- [Room Versions](../../docs/matrix-v1.18-spec/rooms/index.md)
- [Room Events](../../docs/matrix-v1.18-spec/client-server-api.md#room-event-format)
- [Power Levels](../../docs/matrix-v1.18-spec/client-server-api.md#mroompower_levels)
