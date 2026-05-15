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

The runtime listener (`merovingian::homeserver::serve_http` and
`serve_tls_http`) now binds the configured client (and federation, when enabled)
listeners. Client listeners dispatch parsed HTTP/1.1 requests into the
`client_server` Matrix JSON adapter (`handle_client_server_request`) over either
loopback cleartext or configured TLS. Federation and internal compatibility
paths can still dispatch into the legacy local router until those surfaces have
production adapters. Advancing endpoints below to `covered` still requires full
Matrix v1.18 behavior, durable state where applicable, and conformance evidence.

## Client-server API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Authentication | `POST /_matrix/client/v3/register` | `partial` | Matrix JSON body is parsed, local registration is reachable through the client listener, and SQLite-backed local users survive restart. Needs UI auth, registration tokens, PostgreSQL coverage, and conformance fixtures. |
| Authentication | `POST /_matrix/client/v3/login` | `partial` | Password login works for local users with LibSodium-backed hashes, token hashes are SQLite-persisted, and restart-survival is tested. Needs full Matrix login flows, refresh behavior, PostgreSQL coverage, and conformance fixtures. |
| Authentication | `POST /_matrix/client/v3/logout` | `partial` | Local bearer-token logout works through the client listener and token revocation is routed through the persistent store. Needs global logout and conformance fixtures. |
| Authentication | `POST /_matrix/client/v3/logout/all` | `scaffolded` | Route planning exists in the auth boundary. Runtime behavior is not complete. |
| Authentication | `POST /_matrix/client/v3/refresh` | `scaffolded` | Route and token-hashing plan exist. Refresh-token rotation is not implemented. |
| Account | `GET /_matrix/client/v3/account/whoami` | `partial` | Local token identity works through the client listener and is covered after SQLite restart. Needs conformance fixtures. |
| Devices | `GET /_matrix/client/v3/devices` | `partial` | Device listing works through the client listener and is hydrated from SQLite devices. Needs complete device semantics. |
| Devices | `GET /_matrix/client/v3/devices/{deviceId}` | `scaffolded` | Route planning exists. Runtime behavior is incomplete. |
| Devices | `PUT /_matrix/client/v3/devices/{deviceId}` | `partial` | Display-name update works through the client listener. Needs persistence and full validation. |
| Devices | `DELETE /_matrix/client/v3/devices/{deviceId}` | `scaffolded` | Route planning exists. Runtime behavior is incomplete. |
| Rooms | `POST /_matrix/client/v3/createRoom` | `partial` | Local room creation works through the client listener and SQLite-persisted rooms survive restart. Needs full create-room semantics, auth events, and conformance fixtures. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/join` | `partial` | Local join slice works through the client listener and membership writes route through the persistent store. Needs full membership rules and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` | `partial` | Local send slice works through the client listener with Matrix reference-hash event IDs, content hashes, persisted Ed25519 signatures, and previous/auth event DAG rows. SQLite-persisted events survive restart. Needs transaction IDs, full event auth, state resolution, and full response semantics. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` | `partial` | Local state summary works through the client listener and is covered after SQLite restart. Needs full state event retrieval and state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `partial` | In-memory joined-room summary works through the client listener and avoids plaintext event content. Needs incremental sync, filters, presence, device updates, to-device messages, and durable stream tokens. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `partial` | Joined-room list works through the client listener and is hydrated from SQLite memberships. Needs full access checks. |
| Media | `POST /_matrix/media/v3/upload` | `partial` | Local authenticated upload, MIME checks, quarantine, digest, metrics, audit, and metadata persistence are runtime-wired. Needs multipart/content handling through real HTTP and durable blob storage. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `partial` | Local download is runtime-wired. Remote fetch is disabled and fail-closed. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `scaffolded` | Trust and safety route matching and validation exist. Runtime route is not wired. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `partial` | Authenticated key API route shapes are runtime-wired through the client-server adapter with durable server-blind key storage, one-time-key consumption, fallback-key reuse, backup rows, payload redaction, audit records, and SQLite restart coverage. Needs Matrix device-list stream semantics, complete backup retrieval/deletion semantics, full key-count behavior, and conformance fixtures. |

## Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` | `partial` | Inbound transaction handling is runtime-wired through federation listener local-router dispatch with request policy, duplicate handling, canonical JSON request-signature verification, JSON PDU event-signature verification for known keys, and PDU checks. Needs real key discovery, persistence, joins/backfill, and event ingestion. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `scaffolded` | Route planning exists for selected federation surfaces. Full federation behavior is not implemented. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `scaffolded` | Policy checks exist for SSRF/TLS constraints. Network discovery is not implemented. |
| Signing verification | Request and event signatures | `partial` | Federation requests now verify canonical JSON Ed25519 signatures, and JSON PDUs verify Matrix event signatures against known remote key material with CI-covered event-ID API linkage. Needs Matrix key discovery, TLS-bound origin validation, room-version-specific verification, and persisted federation key rotation. |
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
