# Progress tracker

This is the authoritative progress, readiness, and Matrix v1.18 coverage ledger
for The Merovingian. It replaces the older production-readiness,
alpha-readiness, progress, and protocol-coverage notes. Historical numbered
milestone and phase documents are planning notes only; do not use them to decide
whether a capability is ready.

No milestone is complete until every listed `TODO` item for that milestone is
closed and the evidence is recorded in CI or release notes.

## Status model

Use these states consistently:

- `not-started`: no project-owned implementation exists.
- `planned`: route, boundary, or work item is identified, but there is no
  behavior.
- `scaffolded`: types, interfaces, routes, or planning code exist, but there is
  no complete behavior.
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

## Milestone order

### Alpha

Alpha means federation works. The Matrix network is the product; a homeserver
that cannot federate is a single-server preview, not a Matrix homeserver alpha.
Alpha is still a test-user milestone with bugs expected, not a production
deployment milestone.

#### DONE

- Build and warning policy: Meson C++26 build, warnings-as-errors, hardening
  flags, Linux and FreeBSD CI, local build wrappers, WSL wrapper, and named
  debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles exist.
- Secure configuration: validated defaults, bounded config parser, config-file
  metadata checks, reload planning, and smoke tests exist.
- Runtime listener: `merovingian::homeserver::serve_http` and
  `serve_tls_http` bind configured listeners, accept HTTP/1.1 requests, dispatch
  client traffic through the Matrix JSON adapter, and handle shutdown.
- HTTP transport: request-head parsing, request limits, per-endpoint rate-limit
  policies, response serialization, dispatch-mode separation, OpenSSL RAII
  boundary, libcurl-backed outbound HTTPS client, pinned-address DNS through
  `CURLOPT_RESOLVE`, and `MSG_NOSIGNAL` writes exist.
- Authentication and sessions: LibSodium password hashes, CSPRNG access tokens,
  durable token hashes, register/login/logout/whoami/device routes, policy
  checks, durable audit events, and restart-survival coverage exist.
- Local rooms and events: local create/join/send/state/joined_rooms/sync flows
  are runtime-wired with canonical JSON, Matrix content hashes, reference-hash
  event IDs, persisted signing keys, signed runtime event JSON, event DAG rows,
  room-version-aware redaction, v6+ auth rules, v2 state resolution, encrypted
  room policy, and restart-survival coverage.
- Sync foundation: stream tokens, initial sync, incremental event diffing via
  `since`, Matrix-shaped sync responses with event bodies, invite/leave room
  categories, and top-level `presence`, `account_data`, `to_device`,
  `device_lists`, and `device_one_time_keys_count` stubs are implemented.
- E2EE key API foundation: upload/query/claim/cross-signing/signature/backup
  route shapes are runtime-wired with durable server-blind storage,
  one-time-key consumption, fallback-key reuse, backup rows, redaction, audit,
  and SQLite restart coverage.
- Inbound federation foundation: federation listener local-router dispatch,
  inbound transaction scaffold, SSRF/TLS policy checks, duplicate handling,
  canonical JSON Ed25519 request verification, JSON PDU signature verification
  for known keys, signed-request integration coverage, server discovery types,
  outbound transaction types, exponential backoff, circuit-breaker policy,
  `OutboundClient`, `perform_outbound_transaction`, and per-platform TLS
  outbound integration coverage exist.
- Media repository foundation: authenticated local upload/download, MIME
  policy, quarantine/release/remove, LibSodium digest, metrics, audit, metadata
  persistence, and integration coverage exist.
- Database persistence: prepared-statement boundary, schema inventory,
  migration model, in-memory persistent store, SQLite RAII backend,
  current-schema bootstrap, fail-closed hydration, busy timeout, runtime
  hydration, write-through users/devices/tokens/rooms/events/E2EE
  keys/media/audit/admin rows, SQLite rollback coverage, PostgreSQL RAII
  connection/result boundary, PostgreSQL schema bootstrap/hydration/write-through
  path, migration file loading, offline migrator scaffold, database role
  separation, durable trust-and-safety rows, and restart-survival integration
  coverage exist.
- Observability and audit: structured logging, health snapshots, safe metrics
  summaries, redaction helpers, durable audit events, admin health/metrics/audit
  runtime endpoints, and client-server audit persistence exist.
- Trust and safety: registration/account/invite/federation/media/report policy
  engine, runtime client event reporting, admin safety report listing/review,
  durable policy audit rows, and durable admin action rows exist.
- Packaging scaffolds: systemd, OpenRC, BSD rc.d, and Docker assets exist for
  early deployment-shape testing.
- Client discovery: unauthenticated `GET /_matrix/client/versions` returns
  supported versions `v1.1` through `v1.18` with an empty `unstable_features`
  object.
- Response JSON: client-server responses use `canonicaljson::Value` and
  `serialize_canonical` instead of hand-rolled JSON string construction.

#### TODO

1. Publish our signing keys via inbound `GET /_matrix/key/v2/server`, backed by
   the persisted Ed25519 signing key and a canonical self-signed response.
2. Implement server discovery: `.well-known/matrix/server` HTTPS fetch, DNS SRV
   lookup on `_matrix-fed._tcp.<host>`, timeout/error handling, IPv6 handling,
   and private/loopback IP rejection before addresses are pinned into
   `OutboundClient`.
3. Fetch and cache remote signing keys through outbound
   `GET /_matrix/key/v2/server`, verify the self-signed key response, persist
   `valid_until_ts`, refresh on rotation, and wire the cache into inbound
   verification.
4. Persist outbound federation transactions and destination retry state, then
   replay pending rows after restart.
5. Add the outbound dispatch worker that discovers remote servers, builds
   `OutboundCall`, invokes `perform_outbound_transaction`, honors
   `destination_should_retry`, and drains on shutdown.
6. Complete inbound `PUT /_matrix/federation/v1/send/{txnId}` PDU ingestion:
   run auth rules for remote events, append accepted PDUs to the event graph,
   apply state resolution when needed, and handle EDUs such as typing and
   receipts.
7. Implement federation make/send join, leave, invite, and backfill flows.
8. Finish sync conformance: long polling, filters, populated presence,
   account-data, device-list, to-device, and key-count surfaces, plus Matrix
   v1.18 fixtures.
9. Add live PostgreSQL integration coverage and enforce separate runtime and
   migration role grants.
10. Run fuzz targets in CI for canonical JSON and HTTP transport before
   declaring Alpha.
11. Replace placeholder hardening checks with fail-closed alpha deployment
   controls or explicitly documented alpha-only exceptions.

### Beta

Beta means the homeserver has broad Matrix v1.18 behavior coverage, can survive
realistic operator testing, and can federate with selected remote homeservers in
a non-production environment.

#### DONE

- Alpha foundations listed above.
- Federation request signing and PDU signature verification boundaries exist for
  known keys.
- PostgreSQL schema bootstrap, hydration, write-through path, and database role
  separation scaffolding exist.
- Admin health, metrics, audit, media moderation, and trust-and-safety review
  routes exist.

#### TODO

- Complete Matrix v1.18 client-server endpoint coverage for authentication,
  devices, rooms, sync, media, reports, and E2EE key APIs.
- Promote endpoint behavior from `partial` or `scaffolded` to `spec-covered`
  with conformance fixtures.
- Complete federation joins, leaves, invites, backfill, PDU delivery, event
  ingestion, remote key rotation, and TLS-bound origin validation.
- Add live PostgreSQL integration tests that cover restart survival,
  transaction rollback, migration ordering, and role-grant failures.
- Persist federation queues, account data, policy rules, and media blob
  metadata.
- Add media remote fetch, sandboxed processing worker, AV hook boundary,
  thumbnailing, decompression limits, and durable blob storage.
- Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability.
- Add policy server transport integration, durable policy-rule management, and
  richer moderation workflows.
- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers.
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests.

### Production

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

#### DONE

- Packaging files exist for Linux and BSD deployment-shape testing:
  `packaging/systemd/merovingian.service`, `packaging/openrc/merovingian`,
  `packaging/rc.d/merovingian`, and `Dockerfile`.
- Release-readiness script exists and rejects missing required release files or
  known unsafe legacy hashing primitives.
- CodeQL, coverage, sanitizer, static-analysis, and Linux CI jobs install
  LibSodium development headers before configuring Meson.

#### TODO

- Keep real listener coverage in CI and prove the server serves requests until
  stopped by the service manager.
- Require configured TLS with validated certificate and private-key files for
  public listeners; keep loopback cleartext available for reverse-proxy
  deployments.
- Complete full Matrix v1.18 conformance, persistence, endpoint coverage, and
  production-grade rate limiting for client-server routes.
- Store access tokens only as versioned cryptographic hashes generated from
  LibSodium CSPRNG output.
- Store passwords only with LibSodium Argon2id password hashes.
- Verify federation requests and events with Matrix canonical JSON and real
  Ed25519 verification, including discovered and rotated remote keys.
- Keep runtime users, tokens, rooms, events, account data, policy rules,
  federation queues, and media metadata alive across restart for SQLite and
  PostgreSQL.
- Enforce PostgreSQL transaction coverage, migration coverage, and role grants
  against real temporary databases.
- Fail closed when required production hardening controls are unavailable.
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- Add signed release artifacts, reproducible builds, SBOM, dependency pinning
  policy, license review, checksums, provenance, and artifact signatures.
- Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and artifact signatures
  in release notes.

## Immediate priority order

1. Publish own signing keys via inbound `GET /_matrix/key/v2/server`.
2. Implement `.well-known/matrix/server` plus DNS SRV resolution to populate
   the pre-validated address set passed into `OutboundClient`.
3. Fetch and cache remote signing keys through the outbound client, persist the
   outbound transaction queue with replay on restart, build the dispatch worker
   that drives `perform_outbound_transaction`, and complete inbound
   `PUT /send/{txnId}` event ingestion plus make/send join, leave, invite, and
   backfill flows.
4. Add live PostgreSQL integration coverage and runtime/migration role grants.
5. Finish sync long polling, filters, populated top-level sync surfaces, and
   Matrix v1.18 conformance fixtures.
6. Keep the protocol coverage tables in this file up to date with every
   endpoint change.
7. Promote CI from build/test checks to capability gates with conformance,
   fuzzing, platform, packaging, and release evidence.

## Capability ledger

| Capability | Current status | Evidence | Gap |
| --- | --- | --- | --- |
| Build and warning policy | `runtime-wired` | Meson C++26 build, warnings-as-errors, hardening flags, Linux and FreeBSD CI, reusable local build wrappers, WSL bridge wrapper, and named debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Validated defaults, bounded parser, config-file metadata checks, reload planning, smoke tests | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | `net::TcpAcceptor` binds per `ListenerPlan`, `net::ShutdownSignal` handles SIGINT/SIGTERM, `homeserver::serve_http`/`serve_tls_http` accept/parse/dispatch loops, client listeners dispatch through the `client_server` Matrix JSON adapter, `--dry-run` flag for validation-only runs, integration tests exercising loopback HTTP and TLS round-trips | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, per-endpoint rate-limit enforcement keyed by normalized bucket, 429 `M_LIMIT_EXCEEDED` response on quota breach, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, libcurl-backed outbound HTTPS client with peer and hostname verification, redirects refused, https-only protocol, pinned-address DNS, bounded response cap, optional CA trust blob, and `MSG_NOSIGNAL` writes | Upgrade to `llhttp` or reviewed parser boundary, add request body streaming, keep-alive, HTTP/2, per-connection slowloris policy, remote-IP buckets for unauthenticated routes, durable rate-limit state, and operator-tunable policy overrides. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation, send, joined rooms, sync slices, unauthenticated `GET /_matrix/client/versions`, and Matrix v1.18-spec-complete sync response shape are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, conformance coverage, persistence semantics, and populate the top-level sync surfaces with real behavior. |
| Authentication and sessions | `runtime-wired` | LibSodium password hashing, CSPRNG access tokens, durable token hashes, SQLite/PostgreSQL hydration into runtime sessions, client-server register/login/logout/whoami/device routes, policy checks, durable audit events, and restart-survival coverage | Add refresh-token rotation, registration tokens, explicit admin bootstrap controls, account recovery controls, global logout, and Matrix conformance fixtures. |
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, server-blind payload redaction, audit records, and SQLite restart coverage | Add Matrix device-list stream semantics, full key-count algorithms, complete backup version/session retrieval/deletion, Matrix v1.18 semantics, and conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | Strict canonical JSON parser boundary, deterministic serializer, event envelope, content hashes, reference-hash event IDs, redacted signing payloads, Base64 Ed25519 signature attachment/verification, persisted runtime signing key, signed runtime event JSON, durable event DAG rows, room-version-aware redaction, v6+ auth rules, state resolution v2, incremental sync with stream tokens and `since`, Matrix-shaped sync responses with `rooms.join`, `rooms.invite`, `rooms.leave`, and top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys, encrypted-room policy, local room flow, and restart-survival integration coverage | Add sync long polling and filters, real payloads for presence/device/to-device/account-data surfaces, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through the local router, inbound transaction scaffold, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known remote keys, signed-request integration coverage, server discovery module, outbound transaction types with exponential backoff and circuit breaker policy, `merovingian::http::OutboundClient`, `perform_outbound_transaction` wiring, X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, circuit-breaker short-circuit before network I/O, and per-platform TLS integration coverage | Publish own signing keys, implement real server discovery, fetch/cache remote keys, add outbound dispatch worker, durable transaction queue persistence with retry delivery, inbound event ingestion, joins/invites/backfill, and TLS-bound origin validation. |
| Media repository | `runtime-wired` | Runtime media routes for authenticated local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit, persistent metadata writes, and integration coverage | Add sandboxed processing worker, remote fetch, AV hook boundary, thumbnailing, decompression limits, and durable blob storage. |
| Database persistence | `runtime-wired` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/E2EE keys/media/audit/admin rows, SQLite transaction rollback, atomic runtime helpers, dependency reviews, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/hydration/write-through path, migration-file loading, offline migrator scaffold, database role separation, durable trust-and-safety rows, and restart-survival integration coverage | Add live PostgreSQL integration tests, enforce runtime/migration grants through separate PostgreSQL users, and full persistence for federation queues, account data, policy rules, and media blob metadata. |
| Observability and audit | `runtime-wired` | Structured logging, health snapshots, safe metrics summaries, redaction helpers, durable audit events, admin health/metrics/audit runtime endpoints, and client-server action audit persistence | Add production scrape/export contract, log format contract, trace correlation, and operator docs. |
| Trust and safety | `runtime-wired` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes, runtime client event reporting, admin safety report listing/review, durable policy audit rows, and durable admin action rows | Add Matrix v1.18 conformance fixtures, policy server transport integration, durable policy-rule management, and richer moderation workflows. |
| Runtime hardening | `scaffolded` | Systemd/OpenRC/rc.d packaging, hardening plan, and self-check surfaces | Enforce fail-closed controls, implement seccomp/AppArmor/Landlock notes or profiles, OpenBSD pledge/unveil, and FreeBSD Capsicum where practical. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `scaffolded` | Canonical JSON and HTTP fuzz targets can be built | Run fuzz targets in CI, add corpus management, Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `scaffolded` | Release-readiness script and packaging skeletons exist | Add SBOM, dependency pinning policy, license review, artifact signing, checksums, provenance, and reproducible build notes. |

## Matrix v1.18 protocol coverage

An endpoint is not `covered` until it is runtime-wired, backed by durable state
where required, and checked by behavior tests or conformance fixtures.

Coverage states:

- `not-started`: no route or behavior exists.
- `planned`: route or boundary is identified, but there is no behavior.
- `scaffolded`: route or helper exists with placeholder behavior.
- `partial`: behavior works for a restricted local slice.
- `covered`: Matrix v1.18 behavior is implemented, tested, and documented.
- `blocked`: implementation depends on an unfinished lower-level capability.

The runtime listener binds configured client listeners and, when enabled,
federation listeners. Client listeners dispatch parsed HTTP/1.1 requests into
`handle_client_server_request` over loopback cleartext or configured TLS.
Federation and internal compatibility paths can still dispatch into the legacy
local router until those surfaces have production adapters.

### Client-server API

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
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` | `partial` | Local send slice works through the client listener with Matrix reference-hash event IDs, content hashes, persisted Ed25519 signatures, previous/auth event DAG rows, and full v6+ auth checking against current room state before persistence. Needs transaction IDs, restricted join rule evaluation, third-party invite auth, incremental sync completion, and conformance fixtures. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` | `partial` | Local state summary works through the client listener and is covered after SQLite restart. Needs full state event retrieval and state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `partial` | Sync returns Matrix v1.18-shaped JSON with event bodies in timelines, stream-token-based `next_batch`, and incremental diffing when `since` is provided. `rooms.join`, `rooms.invite`, and `rooms.leave` are emitted from `PersistentMembership`; top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys are emitted with empty payloads. Needs populated payloads behind those keys, filters, long polling, presence updates, device-list change tracking, to-device messages, and durable stream tokens. |
| Discovery | `GET /_matrix/client/versions` | `partial` | The unauthenticated spec discovery endpoint answers before the auth check with the versions array `v1.1` through `v1.18` and an empty `unstable_features` object. Needs feature flags for unstable spec extensions once adopted. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `partial` | Joined-room list works through the client listener and is hydrated from SQLite memberships. Needs full access checks. |
| Media | `POST /_matrix/media/v3/upload` | `partial` | Local authenticated upload, MIME checks, quarantine, digest, metrics, audit, and metadata persistence are runtime-wired. Needs multipart/content handling through real HTTP and durable blob storage. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `partial` | Local download is runtime-wired. Remote fetch is disabled and fail-closed. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `partial` | Authenticated event reports are runtime-wired through the client-server adapter, validated by the trust-and-safety policy engine, and appended to durable policy audit rows. Needs Matrix v1.18 conformance fixtures and richer report storage/query semantics. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `partial` | Authenticated key API route shapes are runtime-wired through the client-server adapter with durable server-blind key storage, one-time-key consumption, fallback-key reuse, backup rows, payload redaction, audit records, and SQLite restart coverage. Needs Matrix device-list stream semantics, complete backup retrieval/deletion semantics, full key-count behavior, and conformance fixtures. |

### Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (inbound) | `partial` | Inbound transaction handling is runtime-wired through federation listener local-router dispatch with request policy, duplicate handling, canonical JSON request-signature verification, JSON PDU event-signature verification for known keys, and PDU checks. Needs remote key discovery, PDU ingestion into the room event graph, joins/backfill, and EDU handling. |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (outbound) | `partial` | `perform_outbound_transaction` composes the libcurl-backed `merovingian::http::OutboundClient` with X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, and circuit-breaker short-circuit through `destination_should_retry`. Per-platform TLS integration coverage exercises valid round-trip, hostname mismatch, untrusted self-signed, and 3xx rejection. Needs the dispatch worker that produces pending transactions plus durable queue persistence and replay on restart. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `scaffolded` | Route planning exists for selected federation surfaces. Full make/send join, leave, invite, and backfill behavior is not implemented. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `scaffolded` | Policy checks exist for SSRF/TLS constraints. Server discovery module parses well-known delegation, extracts host/port, rejects private IPs. `FederationDestination` tracks retry state. `OutboundClient` pins addresses via `CURLOPT_RESOLVE` but does not resolve hostnames itself; the federation security policy must hand it pre-validated addresses. Network discovery is not yet implemented. |
| Signing verification | Request and event signatures | `partial` | Federation requests verify canonical JSON Ed25519 signatures, and JSON PDUs verify Matrix event signatures against known remote key material with CI-covered event-ID API linkage. Outbound requests are signed through the shared `make_federation_signature` primitive. Needs Matrix key discovery, TLS-bound origin validation, room-version-specific verification, persisted federation key rotation, and inclusion of the destination server name in the X-Matrix payload to match newer Matrix spec versions. |
| Key publication | `GET /_matrix/key/v2/server` (inbound) | `not-started` | No endpoint exists. Required so remote homeservers can fetch our Ed25519 signing key and verify our federation requests. Without this no peer can accept anything we send. |
| Federation queues | Outbound federation and retry/backoff | `partial` | `OutboundClient` is wired through `perform_outbound_transaction` with retry-state mutation via `apply_outbound_result` and circuit-breaker short-circuit via `destination_should_retry`. Needs durable persistence of pending transactions to `federation_transactions`, restart replay, and the dispatch worker that pulls pending rows and drives delivery. |

### Server administration and operations

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Health | `GET /_merovingian/admin/health` | `partial` | In-process admin health exists and is reachable over the TCP listener via the legacy local router. Needs a real admin auth model, JSON response shape, and deployment checks. |
| Media moderation | Quarantine, release, remove, metrics | `partial` | Admin media actions exist locally with audit and metrics. Needs durable storage, authorization model, and operator docs. |
| Trust and safety review | Reports and admin review | `partial` | Admin safety report listing and review actions are runtime-wired through authenticated client-server routes with durable policy audit and admin action rows. Needs policy rule management, Matrix v1.18 fixtures, and policy server transport. |
| Metrics | Exported metrics | `partial` | Admin metrics summaries are runtime-wired and avoid secret fields. Needs production scrape/export contract and trace correlation. |

## Completed capability notes

### Incremental sync foundation

- `merovingian::sync::StreamToken` stores hex-based `event_ordering` and
  `membership_ordering` fields with encode/decode/validate BDD coverage.
- `merovingian::core::SyncRequest` parses `since`, `timeout`, `full_state`,
  and `filter` query parameters.
- Schema migration v5 added `stream_ordering` columns to `events`,
  `membership`, and `invites`; added `membership` type to `membership`; and
  added `event_id` to `invites`.
- `PersistentEvent` and `PersistentMembership` include `stream_ordering`;
  `LocalDatabase` tracks `next_stream_ordering`.
- `sync_json` returns Matrix-shaped sync JSON with event bodies in timelines,
  stream-token-based `next_batch`, and incremental diffing.

### Outbound federation foundation

- `merovingian::federation::ServerDiscoveryResult` resolves server names from
  well-known delegation URLs, extracts host/port, rejects private IPv4/IPv6
  ranges, and validates server-name shape.
- `merovingian::federation::FederationDestination` tracks retry state for
  durable outbound queue processing.
- `merovingian::federation::OutboundTransaction` tracks pending PDUs/EDUs with
  method, target, origin, body, and retry metadata.
- `make_outbound_transaction()` constructs outbound transactions.
- `compute_backoff()` implements exponential backoff with a 2 second base and
  5 minute cap.
- `destination_should_retry()` opens the circuit after 3 consecutive failures
  and respects backoff expiry.

### Federation outbound HTTP and canonical responses

- `merovingian::http::OutboundClient` is a libcurl-backed HTTPS client for
  federation traffic. Requests run with peer verification, strict hostname
  verification, redirects refused, HTTPS-only protocol, signal-driven
  resolution disabled, explicit connect and total timeouts, bounded response
  body capture, and caller-supplied pinned addresses bound through
  `CURLOPT_RESOLVE`.
- `OutboundError` provides stable names for invalid URL/method, cleartext URL,
  unresolved host, TLS verification failure, connection failure, redirect
  rejection, oversized response, timeout, and generic network error.
- `OutboundCall` composes an outbound transaction with validated destination
  resolution and signing identity.
- `build_outbound_request()` builds the outbound HTTP request, including the
  `X-Matrix` Authorization header through `make_federation_signature`.
- `apply_outbound_result()` updates destination retry state after success or
  failure.
- `perform_outbound_transaction()` short-circuits when the circuit breaker is
  open, otherwise calls `OutboundClient::perform()` and applies the result.
- Per-platform TLS integration coverage drives a local TLS server through valid
  round-trip, hostname mismatch, untrusted self-signed certificate, and 3xx
  rejection scenarios.
- Client-server JSON responses now use `canonicaljson::Value` plus
  `serialize_canonical`; stored device-key payloads are parsed before
  re-serialization so malformed stored data surfaces as well-formed `null`.

## Single-server preview path

Before federation work completes, a closed test group can exercise the server as
a single homeserver with these caveats:

- No federation; users can only talk to users on the same instance.
- No remote media; local upload and download work, remote fetches fail closed.
- `GET /_matrix/client/versions` advertises `v1.1` through `v1.18` and empty
  `unstable_features`, so modern clients can proceed past discovery.
- E2EE can show unverified-device warnings until end-to-end verification,
  cross-signing, and key-sharing flows are proven.

## Release command sequence

```sh
sh scripts/setup-dev-env.sh --check-only
meson setup build -Dbuild_tests=true -Dbuild_fuzz=true
meson compile -C build
meson test -C build --print-errorlogs
sh scripts/reject-unsafe.sh
sh scripts/check-release-readiness.sh
```

These commands are the minimum release evidence path. The release operator must
also record dependency versions, test logs, sanitizer logs, fuzz target names,
package checksums, and artifact signatures in release notes.
