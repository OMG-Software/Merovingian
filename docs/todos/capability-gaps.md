# Capability Gaps

Open work per capability area. Status column reflects the current level in the
`not-started → planned → scaffolded → unit-covered → integrated → runtime-wired
→ spec-covered → production-gated` ladder.

## Capability ledger

| Capability | Status | Gap |
| --- | --- | --- |
| Build and warning policy | `runtime-wired` | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | Upgrade to `llhttp` or reviewed parser boundary, add request body streaming, keep-alive, HTTP/2, per-connection slowloris policy, remote-IP buckets for unauthenticated routes, durable rate-limit state, and operator-tunable policy overrides. |
| Client-server API | `runtime-wired` | Complete Matrix v1.18 endpoint coverage, conformance coverage, persistence semantics, and populate the top-level sync surfaces with real behavior. |
| Authentication and sessions | `runtime-wired` | Add richer operator bootstrap lifecycle controls, account recovery controls, and Matrix conformance fixtures for remaining auth flows. |
| E2EE key APIs | `runtime-wired` | Add full key-count algorithms, complete backup session retrieval/deletion, broader Matrix v1.18 semantics, and remaining conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | Add sync long polling and filters, real payloads for presence/device/to-device/account-data surfaces, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Room-version-specific PDU verification, key rotation publication, multiple active/old keys, and Matrix federation conformance coverage. |
| Media repository | `runtime-wired` | Live remote media transport and server discovery wired in v0.7.2. Thumbnail records now carry actual content type and byte size (dimensions remain 0×0 until an image decoder is linked). Remaining: real image resampling library integration, multipart upload handling, and Matrix v1.18 remote-thumbnail conformance fixtures. |
| Database persistence | `runtime-wired` | Add more live PostgreSQL integration tests and enforce runtime/migration grants through separate PostgreSQL users in deployment packaging. |
| Observability and audit | `runtime-wired` | Add production scrape/export contract, log format contract, trace correlation, and operator docs. |
| Trust and safety | `runtime-wired` | Add Matrix v1.18 conformance fixtures, policy server transport integration, durable policy-rule management, and richer moderation workflows. |
| Runtime hardening | `integrated` | ELF program-header probe (linker/RELRO) retired in v0.7.2; seccomp-bpf allowlist applied and probe retired in v0.7.2. Remaining: harden default action to `SECCOMP_RET_KILL_PROCESS` after allowlist validation, OpenBSD pledge/unveil, FreeBSD Capsicum, optional in-process privilege drop, Landlock confinement, and `RLIMIT_CORE` clamp. |
| Platform support | `integrated` | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `integrated` | Add durable corpus management, broader Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `integrated` | Add dependency pinning policy, license review, artifact signing, provenance, and reproducible build notes. |

## Protocol coverage gaps

### Client-server API

| Endpoint | Status | Needs |
| --- | --- | --- |
| `GET /_matrix/client/v1/auth_metadata`, MSC2965 OIDC | `partial` | Real OIDC support; currently returns 404 M_UNRECOGNIZED as unsupported signal. |
| `GET /_matrix/client/v3/voip/turnServer` | `partial` | Real TURN credential issuance; currently returns empty 200. |
| `GET /_matrix/media/v3/thumbnail/*`, `GET /_matrix/client/v1/media/thumbnail/*` | `runtime-wired` | Real image resampling, remote thumbnail fetch, and v1.18 conformance fixtures. |
| `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}` | `spec-covered` | |
| `POST /_matrix/client/v3/user_directory/search` | `spec-covered` | |
| `GET /_matrix/client/v3/sync` | `spec-covered` | Wire `filter_id` query parameter, unread-notification/summary semantics, durable stream tokens. |
| `POST /_matrix/client/v3/account/password` | `spec-covered` | UI-auth re-authentication and `logout_devices` handling. |
| `POST /_matrix/client/v3/createRoom` | `spec-covered` | Broader conformance fixtures. |
| `POST /_matrix/client/v3/rooms/{roomId}/join` | `spec-covered` | Federation-aware joins. |
| `POST /_matrix/client/v3/join/{roomIdOrAlias}` | `spec-covered` | Room-alias resolution, `?server_name` hint, federation-aware joins. |
| `POST /_matrix/client/v3/rooms/{roomId}/send` | `spec-covered` | Restricted join rule evaluation, third-party invite auth. |
| `PUT /_matrix/client/v3/user/{userId}/account_data/{type}` | `spec-covered` | Room-scoped account data (`/rooms/{roomId}/account_data/{type}`). |
| Push rule CRUD | `spec-covered` | Writable push-rule CRUD (PUT/DELETE/enabled/actions). |
| `PUT /_matrix/client/v3/profile/{userId}/avatar_url` | `spec-covered` | Integration tests only; needs v1.18 conformance fixture. |

### Federation API

| Endpoint | Status | Needs |
| --- | --- | --- |
| `PUT /_matrix/federation/v1/send/{txnId}` inbound | `runtime-wired` | Room-version-specific PDU verification, richer EDU side-effects. Idempotency, unknown-EDU discard, and oversize rejection now conformance-covered. |
| `PUT /_matrix/federation/v1/send/{txnId}` outbound | `partial` | Matrix conformance coverage. |
| Federation join/leave/invite/knock/backfill | `integrated` | Full Matrix conformance fixtures; richer production leave/knock state semantics. make_join M_INCOMPATIBLE_ROOM_VERSION now conformance-covered. |
| Server discovery | `partial` | TLS-bound origin validation, richer Matrix edge-case fixtures, live network conformance coverage. |
| Request and event signing/verification | `partial` | Room-version-specific PDU hash verification, live interoperability test, conformance coverage. |
| `GET /_matrix/federation/v1/query/profile` | `spec-covered` | |
| `GET /_matrix/federation/v1/query/directory` | `spec-covered` | |
| Event-graph queries | `partial` | Historical state-at-event reconstruction, conformance fixtures. |
| Outbound federation queues | `partial` | Live federation delivery coverage. |
| Key publication (`GET /_matrix/key/v2/server`) | `spec-covered` | Key-ID format, valid_until_ts expiry, and old_verify_keys structural contract now covered by conformance fixtures. |

### Server administration

| Endpoint | Status | Needs |
| --- | --- | --- |
| `GET /_merovingian/admin/health` | `partial` | Real admin auth model, JSON response shape, deployment checks. |
| Admin media moderation | `partial` | Richer authorization model, operator docs. |
| Admin trust and safety review | `partial` | Policy rule management, Matrix v1.18 fixtures, policy server transport. |
| Exported metrics | `partial` | Production scrape/export contract, trace correlation. |
| Debug logging | `partial` | Production log-format contract, request trace correlation IDs. |
