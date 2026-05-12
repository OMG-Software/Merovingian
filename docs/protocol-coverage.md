# Matrix v1.18 protocol coverage

This document tracks Matrix v1.18 coverage independently from historical
milestones. An endpoint is not `covered` until it is runtime-wired, backed by
durable state where required, and checked by behavior tests or conformance
fixtures.

## Coverage states

- `not-started`: no route or behavior exists.
- `planned`: route or boundary is identified, but there is no behavior.
- `scaffolded`: route or helper exists with placeholder behavior.
- `partial`: behavior works for a restricted local slice.
- `covered`: Matrix v1.18 behavior is implemented, tested, and documented.
- `blocked`: implementation depends on an unfinished lower-level capability.

## Listener wiring

The runtime listener (`merovingian::homeserver::serve_http`) now binds the
configured client (and federation, when enabled) listeners. Client listeners
dispatch parsed HTTP/1.1 requests into the `client_server` Matrix JSON adapter
(`handle_client_server_request`). Federation and internal compatibility paths
can still dispatch into the legacy local router until those surfaces have
production adapters. Advancing endpoints below to `covered` still requires full
Matrix v1.18 behavior, durable state where applicable, and conformance evidence.

## Client-server API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Authentication | `POST /_matrix/client/v3/register` | `partial` | Matrix JSON body is parsed and local registration is reachable through the client listener. Needs UI auth, registration tokens, persistence, and conformance fixtures. |
| Authentication | `POST /_matrix/client/v3/login` | `partial` | Password login works for local users with LibSodium-backed hashes and is reachable through the client listener. Needs full Matrix login flows, refresh behavior, persistence, and conformance fixtures. |
| Authentication | `POST /_matrix/client/v3/logout` | `partial` | Local bearer-token logout works through the client listener. Needs durable token revocation. |
| Authentication | `POST /_matrix/client/v3/logout/all` | `scaffolded` | Route planning exists in the auth boundary. Runtime behavior is not complete. |
| Authentication | `POST /_matrix/client/v3/refresh` | `scaffolded` | Route and token-hashing plan exist. Refresh-token rotation is not implemented. |
| Account | `GET /_matrix/client/v3/account/whoami` | `partial` | Local token identity works through the client listener. Needs persistence. |
| Devices | `GET /_matrix/client/v3/devices` | `partial` | In-memory device listing works through the client listener. Needs durable device storage and complete device semantics. |
| Devices | `GET /_matrix/client/v3/devices/{deviceId}` | `scaffolded` | Route planning exists. Runtime behavior is incomplete. |
| Devices | `PUT /_matrix/client/v3/devices/{deviceId}` | `partial` | Display-name update works through the client listener. Needs persistence and full validation. |
| Devices | `DELETE /_matrix/client/v3/devices/{deviceId}` | `scaffolded` | Route planning exists. Runtime behavior is incomplete. |
| Rooms | `POST /_matrix/client/v3/createRoom` | `partial` | Local room creation works through the client listener. Needs full create-room semantics, auth events, persistence, and conformance fixtures. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/join` | `partial` | Local join slice works through the client listener. Needs full membership rules and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` | `partial` | Local send slice works through the client listener. Needs transaction IDs, event auth, event IDs, signatures, DAG persistence, and full response semantics. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` | `partial` | Local state summary works through the client listener. Needs full state event retrieval and state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `partial` | In-memory joined-room summary works through the client listener and avoids plaintext event content. Needs incremental sync, filters, presence, device updates, to-device messages, and durable stream tokens. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `partial` | In-memory joined-room list works through the client listener. Needs persistence and full access checks. |
| Media | `POST /_matrix/media/v3/upload` | `partial` | Local authenticated upload, MIME checks, quarantine, digest, and metrics exist. Needs multipart/content handling through real HTTP and durable storage. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `partial` | Local download exists. Remote fetch is disabled and fail-closed. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `scaffolded` | Trust and safety route matching and validation exist. Runtime route is not wired. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `scaffolded` | Planning boundary exists. Runtime behavior and persistence are not implemented. |

## Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` | `partial` | Inbound transaction scaffold exists with request policy, duplicate handling, and PDU checks. Needs real Matrix signing, canonical JSON, persistence, and event ingestion. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `scaffolded` | Route planning exists for selected federation surfaces. Full federation behavior is not implemented. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `scaffolded` | Policy checks exist for SSRF/TLS constraints. Network discovery is not implemented. |
| Signing verification | Request and event signatures | `scaffolded` | Placeholder signing/hash behavior exists in places. Must be replaced with Matrix canonical JSON and Ed25519 verification. |
| Federation queues | Outbound federation and retry/backoff | `not-started` | Runtime worker and persistence model are not implemented. |

## Server administration and operations

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Health | `GET /_merovingian/admin/health` | `partial` | In-process admin health exists and is reachable over the TCP listener via the legacy local router. Needs a real admin auth model, JSON response shape, and deployment checks. |
| Media moderation | Quarantine, release, remove, metrics | `partial` | Admin media actions exist locally with audit and metrics. Needs durable storage, authorization model, and operator docs. |
| Trust and safety review | Reports and admin review | `scaffolded` | Policy engine and route matching exist. Runtime integration is incomplete. |
| Metrics | Exported metrics | `scaffolded` | Internal metric samples exist. No production scrape/export contract yet. |

## Coverage rules

Every protocol change must update this file in the same pull request. Add a
behavior test before moving an item forward, and do not mark an item `covered`
until the real runtime path, persistence requirements, and Matrix v1.18 behavior
are all exercised.
