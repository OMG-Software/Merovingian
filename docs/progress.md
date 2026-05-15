# Project progress

This is the authoritative progress ledger for The Merovingian. The older
numbered milestone and phase documents are historical notes only; do not use
them to decide whether a capability is production-ready.

## Status model

Use these states consistently:

- `not-started`: no project-owned implementation exists.
- `scaffolded`: types, interfaces, or planning code exist, but there is no
  complete behavior.
- `unit-covered`: behavior exists behind unit tests, but is not wired into the
  runtime path.
- `integrated`: behavior is composed with neighbouring modules in integration
  tests.
- `runtime-wired`: behavior is served through the real executable/runtime path.
- `spec-covered`: behavior is checked against Matrix v1.18 fixtures or
  conformance tests.
- `production-gated`: release, security, CI, fuzz, sanitizer, and deployment
  gates pass for the capability.

No capability is production-ready until it reaches `production-gated`.

## Capability ledger

| Capability | Current status | Evidence | Production gap |
| --- | --- | --- | --- |
| Build and warning policy | `runtime-wired` | Meson C++26 build, warnings-as-errors, hardening flags, Linux and FreeBSD CI, reusable local build wrappers, WSL bridge wrapper, and named debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Validated defaults, bounded parser, config-file metadata checks, reload planning, smoke tests | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | `net::TcpAcceptor` binds per `ListenerPlan`, `net::ShutdownSignal` handles SIGINT/SIGTERM, `homeserver::serve_http`/`serve_tls_http` accept/parse/dispatch loops, client listeners dispatch through the `client_server` Matrix JSON adapter, `--dry-run` flag for validation-only runs, integration tests exercising loopback HTTP and TLS round-trips | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, and `MSG_NOSIGNAL` writes | `llhttp` or reviewed parser boundary upgrade, request body streaming, keep-alive, HTTP/2, and runtime application of the slowloris policy. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation, send, joined rooms, and sync slices are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, add conformance coverage, and persist runtime state. |
| Authentication and sessions | `runtime-wired` | LibSodium password hashing, CSPRNG access tokens, durable token hashes, SQLite/PostgreSQL hydration into runtime sessions, client-server register/login/logout/whoami/device routes, policy checks, durable audit events, and restart-survival coverage | Add refresh-token rotation, registration tokens, explicit admin bootstrap controls, account recovery controls, global logout, and Matrix conformance fixtures. |
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, server-blind payload redaction, audit records, and SQLite restart coverage | Add Matrix device-list stream semantics, full key-count algorithms, complete backup version/session retrieval/deletion, Matrix v1.18 semantics, and conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | `yyjson`-backed strict canonical JSON parser boundary, deterministic serializer, event envelope, Matrix content hashes, reference-hash event IDs, redacted canonical signing payloads, Matrix Base64 Ed25519 signature attachment/verification boundary, persisted runtime signing key, signed runtime event JSON, durable previous/auth/signature event DAG rows, room-version-aware redaction, full v6+ auth rules (14-step spec algorithm with create/join/invite/leave/ban/power-level/join-rule checks), auth-event map from current room state, auth checking wired into event send path (conditional on create event presence for bootstrap compatibility), creator-implicit join and power-level-100 bootstrapping, v2 state resolution (conflicted/unconflicted partition, reverse topological power sort, mainline ordering, iterative auth-based conflict resolution), incremental sync with stream tokens and `since` parameter support, Matrix v1.18-compliant sync response with event bodies in timelines, encrypted-room policy, local room flow, client listener dispatch for create/join/send/state/joined_rooms/sync, and restart-survival integration coverage | Add incremental sync with long polling and filters, invite/leave room categories in sync, presence, device updates, to-device messages, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through the local router, inbound transaction scaffold, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known remote keys, signed-request integration coverage, server discovery module (well-known delegation parsing, private IP rejection, FederationDestination retry state), and outbound transaction types with exponential backoff and circuit breaker policy | Implement real server discovery (DNS SRV, well-known HTTPS fetch, key fetch from `/_matrix/key/v2/server`), outbound HTTP client for federation requests, durable transaction queue persistence with retry delivery, joins/invites/backfill, event ingestion, and TLS verification against remote origins. |
| Media repository | `runtime-wired` | Runtime media routes for authenticated local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit, persistent metadata writes, and integration coverage | Add sandboxed processing worker, remote fetch, AV hook boundary, thumbnailing, decompression limits, and durable blob storage. |
| Database persistence | `runtime-wired` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/E2EE keys/media/audit/admin rows, SQLite transaction rollback, atomic runtime helpers for device/token, room/membership, event/current-state, and key writes, dependency reviews under `docs/dependencies/`, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/hydration/write-through path, physical migration-file loading, offline migrator scaffold, database role separation, durable trust-and-safety audit/admin action rows, and restart-survival integration coverage | Add live PostgreSQL integration tests, enforce runtime/migration grants through separate PostgreSQL users, and full persistence for federation queues, account data, policy rules, and media blob metadata. |
| Observability and audit | `runtime-wired` | Structured logging, health snapshots, safe metrics summaries, redaction helpers, durable audit events, admin health/metrics/audit runtime endpoints, and client-server action audit persistence | Add production scrape/export contract, log format contract, trace correlation, and operator docs. |
| Trust and safety | `runtime-wired` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes, runtime client event reporting, admin safety report listing/review, durable policy audit rows, and durable admin action rows | Add Matrix v1.18 conformance fixtures, policy server transport integration, durable policy-rule management, and richer moderation workflows. |
| Runtime hardening | `scaffolded` | Systemd/OpenRC/rc.d packaging, hardening plan and self-check surfaces | Enforce fail-closed controls, implement seccomp/AppArmor/Landlock notes or profiles, OpenBSD pledge/unveil, FreeBSD Capsicum where practical. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `scaffolded` | Canonical JSON and HTTP fuzz targets can be built | Run fuzz targets in CI, add corpus management, Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `scaffolded` | Release-readiness script and packaging skeletons exist | Add SBOM, dependency pinning policy, license review, artifact signing, checksums, provenance, and reproducible build notes. |

## Immediate priority order

1. Add live PostgreSQL integration coverage and runtime/migration role grants.
2. Implement incremental sync with long polling, filters, invite/leave room
   categories, and durable stream tokens.
3. Implement outbound federation HTTP client, server key discovery
   (`/_matrix/key/v2/server`), well-known/DNS resolution, durable transaction
   persistence with retry delivery, and joins/invites/backfill event ingestion.
4. Keep `docs/protocol-coverage.md` up to date with every endpoint change.
5. Promote CI from build/test checks to capability gates with conformance,
   fuzzing, platform, packaging, and release evidence.

## Completed capability details

### Incremental sync (v0.1.39–v0.1.40, PR #75)

- `merovingian::sync::StreamToken` with hex-based `event_ordering` and
  `membership_ordering` fields; encode/decode/validate with BDD coverage.
- `merovingian::core::SyncRequest` with `since`, `timeout`, `full_state`,
  `filter` optional fields parsed from URL query strings via
  `parse_query_params`; `percent_decode` for URL-encoded filter values.
- Schema migration v5: `stream_ordering` column on `events`, `membership`,
  and `invites`; `membership` type column on `membership`; `event_id` on
  `invites`.
- `PersistentEvent` and `PersistentMembership` gain `stream_ordering`;
  `LocalDatabase` tracks `next_stream_ordering` (monotonic, hydrated from
  max on restart).
- `sync_json` rewritten: Matrix v1.18-compliant JSON with actual event
  bodies in timelines, stream-token-based `next_batch`, incremental diffing
  when `since` token is provided.
- `/sync` route uses `starts_with` to accept query parameters.

### Outbound federation foundation (v0.1.41, PR #76)

- `merovingian::federation::ServerDiscoveryResult`: resolves server names
  from well-known delegation URLs, extracts host/port with IPv4/IPv6 private
  range rejection, validates server name format.
- `merovingian::federation::FederationDestination`: tracks server name, retry
  state (consecutive failures, next retry timestamp, circuit breaker state)
  for durable outbound queue processing.
- `merovingian::federation::OutboundTransaction`: tracks pending PDUs/EDUs
  to remote servers with method/target/origin/body and retry metadata.
- `make_outbound_transaction()`: factory for constructing outbound
  transactions.
- `compute_backoff()`: exponential backoff with 2 s base and 5 min cap.
- `destination_should_retry()`: circuit breaker policy that opens after 3
  consecutive failures and respects backoff expiry.
- BDD coverage for transaction creation, backoff computation, circuit
  breaker behavior, server discovery, and private IP rejection.

### Remaining outbound federation work

The foundational types and policies are in place but the following are still
needed:

1. **Outbound HTTP client**: A TLS-enabled HTTP/1.1 client for making
   federation requests to remote homeservers. Requires integration with the
   existing OpenSSL RAII boundary and the `net::TcpAcceptor` socket layer.
   Must support `PUT /_matrix/federation/v1/send/{txnId}` and
   `GET /_matrix/key/v2/server` at minimum.

2. **Server key discovery**: Fetch and verify remote server signing keys via
   `GET https://<server>/.well-known/matrix/server` (delegation) and
   `GET /_matrix/key/v2/server`. Cache keys in `server_signing_keys` table
   with expiry tracking. Verify key validity_ts against wall clock.

3. **Well-known and DNS SRV resolution**: Parse `/.well-known/matrix/server`
   JSON response, extract delegated host, perform DNS SRV lookup on
   `_matrix-fed._tcp.<host>`, resolve to IP addresses, verify TLS
   certificates match the resolved host, reject private/loopback IPs.

4. **Durable transaction persistence**: Write outbound transactions to the
   `federation_transactions` table before delivery attempt. On failure, update
   `federation_destinations` with retry state. On success, mark transaction
   as delivered. Recovery on restart: scan pending transactions and resume
   delivery with backoff.

5. **PDU delivery and event ingestion**: Send signed PDUs in federation
   transactions to remote servers. Receive and process inbound join/leave/
   invite/backfill PDUs through the existing route scaffolds. Persist received
   events to the room event graph and update current state.
