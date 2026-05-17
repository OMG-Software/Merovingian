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
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, per-endpoint rate-limit enforcement (login/register 5/60s, keys/devices 30/60s, media 20/60s, federation 120/60s, default 60/60s) keyed by normalized bucket and measured in wall-clock seconds, 429 `M_LIMIT_EXCEEDED` response on quota breach, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, and `MSG_NOSIGNAL` writes | `llhttp` or reviewed parser boundary upgrade, request body streaming, keep-alive, HTTP/2, and runtime application of the slowloris policy. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation, send, joined rooms, sync slices, the unauthenticated `GET /_matrix/client/versions` discovery endpoint, and Matrix v1.18-spec-complete sync response shape (`rooms.join`/`rooms.invite`/`rooms.leave` plus `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` top-level keys) are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, add conformance coverage, persist runtime state, and populate the new top-level sync surfaces with real behaviour. |
| Authentication and sessions | `runtime-wired` | LibSodium password hashing, CSPRNG access tokens, durable token hashes, SQLite/PostgreSQL hydration into runtime sessions, client-server register/login/logout/whoami/device routes, policy checks, durable audit events, and restart-survival coverage | Add refresh-token rotation, registration tokens, explicit admin bootstrap controls, account recovery controls, global logout, and Matrix conformance fixtures. |
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, server-blind payload redaction, audit records, and SQLite restart coverage | Add Matrix device-list stream semantics, full key-count algorithms, complete backup version/session retrieval/deletion, Matrix v1.18 semantics, and conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | `yyjson`-backed strict canonical JSON parser boundary, deterministic serializer, event envelope, Matrix content hashes, reference-hash event IDs, redacted canonical signing payloads, Matrix Base64 Ed25519 signature attachment/verification boundary, persisted runtime signing key, signed runtime event JSON, durable previous/auth/signature event DAG rows, room-version-aware redaction, full v6+ auth rules (14-step spec algorithm with create/join/invite/leave/ban/power-level/join-rule checks), auth-event map from current room state, auth checking wired into event send path (conditional on create event presence for bootstrap compatibility), creator-implicit join and power-level-100 bootstrapping, v2 state resolution (conflicted/unconflicted partition, reverse topological power sort, mainline ordering, iterative auth-based conflict resolution), incremental sync with stream tokens and `since` parameter support, Matrix v1.18-compliant sync response with event bodies in timelines, encrypted-room policy, local room flow, client listener dispatch for create/join/send/state/joined_rooms/sync, and restart-survival integration coverage | Add incremental sync with long polling and filters, invite/leave room categories in sync, presence, device updates, to-device messages, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through the local router, inbound transaction scaffold, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known remote keys, signed-request integration coverage, server discovery module (well-known delegation parsing, private IP rejection, `FederationDestination` retry state), outbound transaction types with exponential backoff and circuit breaker policy, `merovingian::http::OutboundClient` (libcurl-backed, peer + hostname verification, redirects refused, https-only, `CURLOPT_RESOLVE`-pinned DNS, bounded response body cap, optional CA trust blob), `perform_outbound_transaction` wiring (X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, circuit-breaker short-circuit before any network I/O), and per-platform TLS integration coverage exercising valid round-trip, hostname mismatch, untrusted self-signed, and 3xx rejection | Implement real server discovery (DNS SRV, `.well-known/matrix/server` HTTPS fetch, key fetch from `GET /_matrix/key/v2/server`), publish own signing keys via inbound `GET /_matrix/key/v2/server`, add the outbound dispatch worker that consumes pending transactions through `perform_outbound_transaction`, persist the outbound queue durably for replay across restart, complete inbound `PUT /send/{txnId}` ingestion into the event graph, and add make/send join, leave, invite, and backfill flows. |
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
3. Publish own signing keys via inbound `GET /_matrix/key/v2/server`,
   implement `.well-known/matrix/server` plus DNS SRV resolution to populate
   the address set passed into `OutboundClient`, fetch and cache remote
   signing keys through the outbound client, persist the outbound transaction
   queue durably with replay on restart, build the dispatch worker that
   drives `perform_outbound_transaction`, and complete inbound `PUT /send/{txnId}`
   event ingestion plus make/send join, leave, invite, and backfill flows.
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

### Federation outbound HTTP and response JSON canonicalization (v0.1.45–v0.1.49, PR #77)

- `merovingian::http::OutboundClient`: libcurl-backed HTTPS client for
  federation traffic. Every request runs with `CURLOPT_SSL_VERIFYPEER=1`,
  `CURLOPT_SSL_VERIFYHOST=2`, `CURLOPT_FOLLOWLOCATION=0`,
  `CURLOPT_PROTOCOLS_STR="https"`, `CURLOPT_NOSIGNAL=1`, explicit connect
  and total timeouts, and a bounded response body cap. Caller-supplied
  `pinned_addresses` are bound to the URL authority through
  `CURLOPT_RESOLVE` so the connection cannot drift to a different address
  after the federation security policy validates the destination.
- `OutboundError` set: stable, audit-friendly names for `invalid_url`,
  `invalid_method`, `https_required`, `unresolved_host`,
  `tls_verification_failed`, `connection_failed`, `redirect_rejected`,
  `response_too_large`, `timeout`, and `network_error`. 3xx responses
  surface as `redirect_rejected` with the status and headers preserved on
  the result.
- `OutboundCall` composes the existing `OutboundTransaction` shape with
  the validated destination resolution (`resolved_host`, `resolved_port`,
  `pinned_addresses`) and the signing identity (`key_id`, `verify_token`,
  `origin_server_ts`).
- `build_outbound_request`: pure builder producing the
  `merovingian::http::OutboundRequest` for a call, including the
  `X-Matrix` Authorization header constructed through the shared
  `make_federation_signature` primitive.
- `apply_outbound_result`: updates the `FederationDestination` retry state
  based on the result. A 2xx response clears the failure counter and
  records `last_success_ts`; any other outcome increments
  `consecutive_failures` and sets `retry_after_ts` through
  `compute_backoff`.
- `perform_outbound_transaction`: single-attempt wrapper that
  short-circuits to `error == "circuit_open"` and no network I/O when
  `destination_should_retry` rejects the attempt, otherwise calls
  `client.perform()` and applies the result.
- Per-platform TLS integration suite
  (`tests/integration/test_federation_outbound_flow.cpp`) drives a
  one-shot TLS test server through valid round-trip, hostname mismatch,
  untrusted self-signed cert, and 3xx rejection scenarios. The
  integration test process ignores `SIGPIPE` at startup so abrupt peer
  closes during handshake do not kill the test runner.
- libcurl (`libcurl4-openssl-dev` on apt, `libcurl-devel` on dnf and
  zypper, `curl` / `curl-dev` on the BSDs and Alpine, `libcurl4` runtime
  layer in the Dockerfile) is wired through `setup-dev-env.sh`,
  `wsl-setup.sh`, `build-linux.sh`, `build-bsd.sh`, the Dockerfile, and
  every CI workflow. The TLS backend is whatever the system libcurl was
  built against; the integration suite enforces consistent verification
  behavior across Linux, FreeBSD, and OpenBSD in CI.
- Response JSON refactor: every hand-rolled JSON response in
  `src/homeserver/client_server.cpp` now flows through
  `canonicaljson::Value` plus `serialize_canonical`. The local
  `json_escape` helper is deleted; control characters now escape as
  `\u00XX` and UTF-8 is validated by the audit-friendly serializer.
  Stored device key payloads embed through `json_embed_raw`, which
  parses with the canonical parser so malformed stored data surfaces as
  a well-formed `null` rather than corrupting the response.

### Remaining outbound federation work

The transport, retry, and signing primitives are in place. To deliver a
working federated alpha the following are still needed:

1. **Inbound key publication**: `GET /_matrix/key/v2/server` so remote
   homeservers can fetch our Ed25519 signing key and verify our
   federation requests. Without this no peer can accept anything we send.

2. **Server discovery**: `.well-known/matrix/server` HTTPS fetch and DNS
   SRV resolution (`_matrix-fed._tcp.<host>`) to produce the validated
   address set the `OutboundClient` requires as `pinned_addresses`. The
   `OutboundClient` itself does not perform DNS; the federation security
   policy must hand it pre-validated addresses.

3. **Remote key discovery**: Outbound `GET /_matrix/key/v2/server`
   through the new client, cache verified keys in the
   `server_signing_keys` table with `valid_until_ts` tracking, refresh
   on rotation.

4. **Durable outbound queue**: Persist pending transactions to the
   `federation_transactions` table before each dispatch; on restart, scan
   pending rows and resume delivery through
   `perform_outbound_transaction`. The retry-state mutation already
   updates `FederationDestination`; the schema and recovery path remain.

5. **Outbound dispatch worker**: A queue worker that consumes pending
   `OutboundTransaction` rows, calls `discover_server` to populate
   `OutboundCall.resolved_host`/`resolved_port`/`pinned_addresses`, and
   invokes `perform_outbound_transaction`. Today `perform_outbound_transaction`
   is single-shot; no orchestrator drives it.

6. **Inbound `PUT /_matrix/federation/v1/send/{txnId}` ingestion**: The
   verification path is wired; PDU ingestion into the room event graph,
   auth-rule checking for remote events, and EDU handling (typing,
   receipts) remain.

7. **Make/send join, leave, invite, backfill**: Federation room
   participation flows. These compose the outbound client and the
   inbound ingestion path.

8. **TLS-bound origin validation**: The current request signature
   verification accepts known-key requests. Tighten it so the TLS
   certificate presented by the origin (when we initiated the
   connection) is bound to the request origin, and similarly for our
   inbound listener.
