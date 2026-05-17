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
| Devices | `PUT /_matrix/client/v3/devices/{deviceId}` | `partial` | Display-name update works through the client listener and appends durable audit. Needs full persistence of device metadata changes and full validation. |
| Devices | `DELETE /_matrix/client/v3/devices/{deviceId}` | `scaffolded` | Route planning exists. Runtime behavior is incomplete. |
| Rooms | `POST /_matrix/client/v3/createRoom` | `partial` | Local room creation works through the client listener and SQLite-persisted rooms survive restart. Needs full create-room semantics, auth events, and conformance fixtures. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/join` | `partial` | Local join slice works through the client listener and membership writes route through the persistent store. Needs full membership rules and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` | `partial` | Local send slice works through the client listener with Matrix reference-hash event IDs, content hashes, persisted Ed25519 signatures, previous/auth event DAG rows, and full v6+ auth checking against current room state before persistence. Auth is conditional on create event presence for bootstrap compatibility; the room creator is implicitly joined with power level 100. SQLite-persisted events survive restart. Needs transaction IDs, restricted join rule evaluation, third-party invite auth, incremental sync, and conformance fixtures. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` | `partial` | Local state summary works through the client listener and is covered after SQLite restart. Needs full state event retrieval and state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `partial` | Sync returns Matrix v1.18-compliant JSON with actual event bodies in timelines, stream-token-based next_batch for incremental sync, and incremental diffing when a since token is provided. `rooms.join`, `rooms.invite`, and `rooms.leave` are emitted by walking `PersistentMembership` for the requesting user; top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys are emitted with empty payloads so clients see a spec-complete response shape. Needs populated payloads behind those keys, filters, long polling, presence updates, device-list change tracking, to-device messages, and durable stream tokens. |
| Discovery | `GET /_matrix/client/versions` | `partial` | The unauthenticated spec discovery endpoint answers before the auth check with the versions array `v1.1` through `v1.18` and an empty `unstable_features` object. Needs feature flags for unstable spec extensions once we adopt any. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `partial` | Joined-room list works through the client listener and is hydrated from SQLite memberships. Needs full access checks. |
| Media | `POST /_matrix/media/v3/upload` | `partial` | Local authenticated upload, MIME checks, quarantine, digest, metrics, audit, and metadata persistence are runtime-wired. Needs multipart/content handling through real HTTP and durable blob storage. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `partial` | Local download is runtime-wired. Remote fetch is disabled and fail-closed. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `partial` | Authenticated event reports are runtime-wired through the client-server adapter, validated by the trust-and-safety policy engine, and appended to durable policy audit rows. Needs Matrix v1.18 conformance fixtures and richer report storage/query semantics. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `partial` | Authenticated key API route shapes are runtime-wired through the client-server adapter with durable server-blind key storage, one-time-key consumption, fallback-key reuse, backup rows, payload redaction, audit records, and SQLite restart coverage. Needs Matrix device-list stream semantics, complete backup retrieval/deletion semantics, full key-count behavior, and conformance fixtures. |

## Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (inbound) | `partial` | Inbound transaction handling is runtime-wired through federation listener local-router dispatch with request policy, duplicate handling, canonical JSON request-signature verification, JSON PDU event-signature verification for known keys, and PDU checks. Needs remote key discovery, PDU ingestion into the room event graph, joins/backfill, and EDU handling. |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (outbound) | `partial` | `perform_outbound_transaction` composes the libcurl-backed `merovingian::http::OutboundClient` with X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, and circuit-breaker short-circuit through `destination_should_retry`. Per-platform TLS integration coverage exercises valid round-trip, hostname mismatch, untrusted self-signed, and 3xx rejection. Needs the dispatch worker that produces pending transactions plus durable queue persistence and replay on restart. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `scaffolded` | Route planning exists for selected federation surfaces. Full make/send join, leave, invite, and backfill behavior is not implemented. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `scaffolded` | Policy checks exist for SSRF/TLS constraints. Server discovery module parses well-known delegation, extracts host/port, rejects private IPs. `FederationDestination` tracks retry state. `OutboundClient` pins addresses via `CURLOPT_RESOLVE` but does not resolve hostnames itself; the federation security policy must hand it pre-validated addresses. Network discovery (DNS SRV `_matrix-fed._tcp.<host>`, `.well-known/matrix/server` HTTPS fetch, remote key fetch through `GET /_matrix/key/v2/server`) is not yet implemented. |
| Signing verification | Request and event signatures | `partial` | Federation requests now verify canonical JSON Ed25519 signatures, and JSON PDUs verify Matrix event signatures against known remote key material with CI-covered event-ID API linkage. Outbound requests are signed through the shared `make_federation_signature` primitive so outbound and inbound speak a single scheme. Needs Matrix key discovery, TLS-bound origin validation, room-version-specific verification, persisted federation key rotation, and (open work) inclusion of the destination server name in the X-Matrix payload to match newer Matrix spec versions. |
| Key publication | `GET /_matrix/key/v2/server` (inbound) | `not-started` | No endpoint exists. Required so remote homeservers can fetch our Ed25519 signing key and verify our federation requests. Without this no peer can accept anything we send. |
| Federation queues | Outbound federation and retry/backoff | `partial` | `OutboundClient` (libcurl, peer + hostname verification, redirects refused, https-only, pinned-address DNS, bounded response cap) is wired through `perform_outbound_transaction` with retry-state mutation via `apply_outbound_result` and circuit-breaker short-circuit via `destination_should_retry`. Needs durable persistence of pending transactions to `federation_transactions`, restart replay, and the dispatch worker that pulls pending rows and drives delivery. |

## Server administration and operations

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Health | `GET /_merovingian/admin/health` | `partial` | In-process admin health exists and is reachable over the TCP listener via the legacy local router. Needs a real admin auth model, JSON response shape, and deployment checks. |
| Media moderation | Quarantine, release, remove, metrics | `partial` | Admin media actions exist locally with audit and metrics. Needs durable storage, authorization model, and operator docs. |
| Trust and safety review | Reports and admin review | `partial` | Admin safety report listing and review actions are runtime-wired through authenticated client-server routes with durable policy audit and admin action rows. Needs policy rule management, Matrix v1.18 fixtures, and policy server transport. |
| Metrics | Exported metrics | `partial` | Admin metrics summaries are runtime-wired and avoid secret fields. Needs production scrape/export contract and trace correlation. |

## Coverage rules

Every protocol change must update this file in the same pull request. Add a
behavior test before moving an item forward, and do not mark an item `covered`
until the real runtime path, persistence requirements, and Matrix v1.18 behavior
are all exercised.
