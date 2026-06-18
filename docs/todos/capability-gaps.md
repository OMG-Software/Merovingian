# Capability Gaps

Open work per capability area. Status column reflects the current level in the
`not-started → planned → scaffolded → unit-covered → integrated → runtime-wired
→ spec-covered → production-gated` ladder.

## Capability ledger

| Capability | Status | Gap |
| --- | --- | --- |
| Build and warning policy | `runtime-wired` | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | Add per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. Per-connection slowloris enforcement landed via `connection_guard`. |
| HTTP transport | `runtime-wired` | Upgrade to `llhttp` or reviewed parser boundary, add request body streaming, keep-alive, HTTP/2, remote-IP buckets for unauthenticated routes, durable rate-limit state, and operator-tunable policy overrides. Per-connection slowloris policy landed via `connection_guard`. |
| Client-server API | `runtime-wired` | Sync surfaces (long polling, filters, presence, to-device, account-data) now wired. Remaining: OIDC support (`auth_metadata`), TURN credential issuance, remote-thumbnail conformance fixtures, and third-party invite auth. |
| Authentication and sessions | `runtime-wired` | Add richer operator bootstrap lifecycle controls, account recovery controls, and Matrix conformance fixtures for remaining auth flows. |
| E2EE key APIs | `runtime-wired` | Key backup version management, session retrieval, count, and etag landed. Remaining: backup session deletion endpoint wiring, full OTK key-count algorithms for `keys/upload`, broader Matrix v1.18 semantics, and remaining conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | Sync long polling, filters, presence, to-device, account-data, and restricted/restricted_v2 join rule evaluation now wired. Remaining: third-party invite auth and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Room-version-specific PDU verification, simultaneously-active multiple signing keys, and broader Matrix federation conformance coverage. Key-rotation publication with `old_verify_keys` landed in 0.8.6. |
| Media repository | `runtime-wired` | Live remote media transport and server discovery wired in v0.7.2. Real image resampling landed in 0.8.10 via the sandboxed out-of-process `merovingian-thumbnail-worker` (libpng/libjpeg-turbo), generated on demand per requested geometry. Remaining: multipart upload handling and Matrix v1.18 remote-thumbnail conformance fixtures. |
| Database persistence | `runtime-wired` | Enforce runtime/migration grants through separate PostgreSQL users in deployment packaging. Transaction-rollback, migration-ordering, and role-grant durability tests landed in 0.8.6; savepoint isolation and cross-connection isolation/visibility/uniqueness durability tests landed in 0.8.9. |
| Observability and audit | `production-gated` | Prometheus text exposition, bounded admin correlation headers, and structured request correlation landed in 0.8.11. Remaining: operator dashboards and retention/export policy for long-term audit archives. |
| Trust and safety | `runtime-wired` | Remote HTTPS policy-server transport and admin policy-rule management workflows are now wired into registration, room creation, inbound federation, media download, and admin review flows. Remaining: Matrix v1.18 conformance fixtures, moderator queues, and broader workflow coverage. |
| Runtime hardening | `runtime-wired` | ELF program-header probe (linker/RELRO) retired in v0.7.2; seccomp-bpf allowlist with `SECCOMP_RET_KILL_PROCESS` default, `RLIMIT_CORE` clamp, `no_new_privs`, and capability bounding set drop all landed in v0.8.18. Remaining: OpenBSD pledge/unveil, FreeBSD Capsicum, optional in-process privilege drop, and Landlock confinement. |
| Platform support | `runtime-wired` | OpenBSD and NetBSD CI jobs added (full build + test suite per PR via `vmactions/*-vm`), joining Linux/Fedora/FreeBSD as Tier 1; platform runtime tests run on each via the suite; support tiers documented in [platform-support.md](../platform-support.md). Remaining: per-platform hardening parity (pledge/unveil, Capsicum) and richer platform-specific assertions. |
| Fuzzing and conformance | `integrated` | Five new fuzz targets added in 0.8.14 (sync filter, config parser, stream token, query params, SRV record) with checked-in seed corpus and automated seeding in CI. Remaining: property tests, load tests, chaos tests, and broader Matrix conformance suite. |
| Supply chain and release | `runtime-wired` | Debian, Fedora, RHEL-compatible, OpenSUSE, FreeBSD, OpenBSD, and NetBSD packages and release tarballs now carry SLSA provenance attestations via `actions/attest-build-provenance` (verifiable with `gh attestation verify`). Remaining: dependency pinning policy, license review, and reproducible build notes. |

## Protocol coverage gaps

### Client-server API

| Endpoint | Status | Needs |
| --- | --- | --- |
| `GET /_matrix/client/v1/auth_metadata`, MSC2965 OIDC | `partial` | Real OIDC support; currently returns 404 M_UNRECOGNIZED as unsupported signal. |
| `GET /_matrix/client/v3/voip/turnServer` | `partial` | Real TURN credential issuance; currently returns empty 200. |
| `GET /_matrix/media/v3/thumbnail/*`, `GET /_matrix/client/v1/media/thumbnail/*` | `runtime-wired` | Real image resampling (PNG/JPEG, `scale`/`crop`) via the sandboxed worker landed in 0.8.10. Remaining: remote-thumbnail fetch and v1.18 conformance fixtures. |
| `GET /_matrix/client/v1/media/config` | `spec-covered` | |
| `GET /_matrix/client/v3/directory/list/room/{roomId}` | `spec-covered` | |
| `PUT /_matrix/client/v3/directory/list/room/{roomId}` | `spec-covered` | |
| `GET /_matrix/client/v3/rooms/{roomId}/aliases` | `spec-covered` | |
| `GET /_matrix/client/v3/rooms/{roomId}/joined_members` | `spec-covered` | |
| `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}` | `spec-covered` | |
| `POST /_matrix/client/v3/rooms/{roomId}/upgrade` | `spec-covered` | Full state copy (name, topic, join rules, power levels, etc.) to replacement room. |
| `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}` | `spec-covered` | |
| `POST /_matrix/client/v3/user_directory/search` | `spec-covered` | |
| `POST /_matrix/client/v3/delete_devices` | `spec-covered` | |
| `GET /_matrix/client/v3/sync` | `spec-covered` | Unread-notification/summary semantics. `filter_id` parameter now wired and conformance-covered; sync-only stream tokens now bound to the response snapshot for to-device delivery so room keys queued during response construction remain pending for the next sync. |
| `POST /_matrix/client/v3/account/password` | `spec-covered` | UI-auth re-authentication and `logout_devices` handling. |
| `POST /_matrix/client/v3/createRoom` | `spec-covered` | Broader conformance fixtures. |
| `POST /_matrix/client/v3/rooms/{roomId}/join` | `spec-covered` | Federation-aware joins. |
| `POST /_matrix/client/v3/join/{roomIdOrAlias}` | `spec-covered` | Room-alias resolution, `?server_name` hint, federation-aware joins. |
| `POST /_matrix/client/v3/rooms/{roomId}/send` | `spec-covered` | Third-party invite auth. Restricted and restricted_v2 join rule evaluation landed in `events/authorization.cpp`. |
| `PUT /_matrix/client/v3/user/{userId}/account_data/{type}` | `spec-covered` | Room-scoped account data (`/rooms/{roomId}/account_data/{type}`). |
| Push rule CRUD | `spec-covered` | Writable push-rule CRUD (PUT/DELETE/enabled/actions). |
| `PUT /_matrix/client/v3/profile/{userId}/avatar_url` | `spec-covered` | Integration tests only; needs v1.18 conformance fixture. |

### Federation API

| Endpoint | Status | Needs |
| --- | --- | --- |
| `PUT /_matrix/federation/v1/send/{txnId}` inbound | `spec-covered` | Richer EDU side-effects. Idempotency, unknown-EDU discard, oversize rejection, and PDU content-hash verification now conformance-covered. |
| `PUT /_matrix/federation/v1/send/{txnId}` outbound | `spec-covered` | Live signed-transaction interop test against a real Synapse peer landed in 0.8.6 (opt-in `build_live_tests`). |
| Federation join/leave/invite/knock/backfill | `spec-covered` | Richer production leave/knock state semantics (stripped state, knock acceptance flows). |
| Server discovery | `partial` | TLS-bound origin validation, richer Matrix edge-case fixtures, live network conformance coverage. |
| Request and event signing/verification | `spec-covered` | Live signed-request interop test against a real Synapse peer landed in 0.8.6 (opt-in). Inbound PDU content-hash verification wired and conformance-covered. |
| `GET /_matrix/federation/v1/query/profile` | `spec-covered` | |
| `GET /_matrix/federation/v1/query/directory` | `spec-covered` | |
| Event-graph queries | `spec-covered` | `auth_chain`/`auth_chain_ids` transitive-closure reconstruction landed in 0.8.9; historical state-at-event reconstruction for `/state` and `/state_ids` landed in 0.8.10 with conformance fixtures; `resolve_state_v2` with full conflicted/unconflicted partitioning is implemented and conformance-covered. |
| Outbound federation queues | `spec-covered` | Live federation delivery coverage under realistic load. |
| Key publication (`GET /_matrix/key/v2/server`) | `spec-covered` | Key-ID format, valid_until_ts expiry, old_verify_keys structural contract, and key-rotation publication (new key active, retired key in old_verify_keys) now covered by conformance fixtures. |

### Server administration

| Endpoint | Status | Needs |
| --- | --- | --- |
| `GET /_merovingian/admin/health` | `partial` | Real admin auth model, JSON response shape, deployment checks. |
| Admin media moderation | `partial` | Richer authorization model, operator docs. |
| Admin trust and safety review | `runtime-wired` | Matrix v1.18 fixtures, moderator queues, and broader workflow coverage. |
| Exported metrics | `runtime-wired` | Stable Prometheus text exposition contract documented in `docs/observability-audit.md`; `X-Merovingian-Request-Id` and `Traceparent` correlation headers landed in 0.8.11. Remaining: operator dashboards and retention/export policy. |
| Debug logging | `runtime-wired` | Per-module level filtering, wall-clock rate limits, and structured diagnostics with `request_id`/`trace_id`/`span_id` fields landed in 0.5.0/0.8.11. Remaining: formal log-format stability commitment. |
