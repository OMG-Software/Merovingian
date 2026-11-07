# src/rooms/ — Rooms Module

Room creation, membership, power levels, and room version policy enforcement.
Spec authority: ../../docs/matrix-v1.19-spec/client-server-api.md#rooms

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

Support for v3–v12 per Matrix spec v1.19. Room versions 1 and 2 are not supported and are
absent from the registry, so every lookup refuses them (ADR-0076); do not add them back
without implementing their event-ID format, event-ID-domain signature and (v1) state
resolution. Room v12 adds `via` servers for join routing (MSC4291).
See `docs/matrix-v1.19-spec/rooms/index.md` for the feature matrix.

## Encryption policy

`encryption_policy.cpp` decides whether a new room is created encrypted and whether a request
for an unencrypted one is refused. `room_creation_encryption_policy` is the ONLY place that
decides: it takes the preset, DM flag, whether the room can federate, the request and the five
`security.encryption.*` settings (ADR-0445), and `create_room` must not re-derive any of it.
`encryption_request_from_initial_state` reads the request from `initial_state`; the last
`m.room.encryption` entry with an empty state key is the request, and anything but
`m.megolm.v1.aes-sha2` in it is "unencrypted" (fail closed). `encryption_algorithm_is_valid` is the only place that names the valid algorithm; the client
state PUT of `m.room.encryption` (`homeserver/ClientServerRuntime.cpp`) refuses a missing or other `algorithm`
with 400 `M_BAD_JSON` through it (ADR-0448). Room-creation settings: joins and federation
ingest are never checked, and neither does the PUT check apply to federated events. It also provides log-redaction helpers so encrypted payloads never reach the logs in plaintext
(`encrypted_event_payload_is_loggable`, `make_encrypted_event_log_summary`).

The server does **not** reject plaintext events in a room that has `m.room.encryption` state;
the Matrix spec leaves that to clients. `room_is_encrypted()` in `homeserver/ClientServerRuntime.cpp`
is only used to exclude encrypted rooms from search indexing.

## Key spec sections

- [Room Versions](../../docs/matrix-v1.19-spec/rooms/index.md)
- [Room Events](../../docs/matrix-v1.19-spec/client-server-api.md#room-event-format)
- [Power Levels](../../docs/matrix-v1.19-spec/client-server-api.md#permissions)
