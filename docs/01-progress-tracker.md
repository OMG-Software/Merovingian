# Progress tracker

This is the authoritative progress, readiness, and Matrix v1.18 coverage ledger
for The Merovingian. It replaces the older production-readiness,
alpha-readiness, progress, and protocol-coverage notes. Historical numbered
milestone and phase documents are planning notes only; do not use them to decide
whether a capability is ready.

The latest repository code-audit report is tracked in
`docs/security-code-audit-alpha.md`.

The generated Matrix v1.18 Client-Server API reference used to audit endpoint
coverage is tracked in `docs/matrix-v1.18-client-server-api.md`.

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

#### TODO

_None — all Alpha gates are closed. The alpha release itself remains a
separate operator decision once this branch is approved._

#### DONE

- Build and warning policy: Meson C++26 build, warnings-as-errors, hardening
  flags, Linux and FreeBSD CI, local build wrappers, WSL wrapper, and named
  debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles exist.
- Secure configuration: validated defaults, bounded config parser, commented
  operator example config, config-file metadata checks, reload planning, and
  smoke tests exist.
- Runtime listener: `merovingian::homeserver::serve_http` and
  `serve_tls_http` bind configured listeners, accept HTTP/1.1 requests, dispatch
  client traffic through the Matrix JSON adapter, keep the internal federation
  default on loopback port `8009` for reverse-proxy deployments, document
  Apache httpd/nginx proxy examples, and handle shutdown.
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
  room policy, decoded Matrix room path components for browser-encoded join,
  send, and state routes, and restart-survival coverage.
- Sync foundation: stream tokens, initial sync, incremental event diffing via
  `since`, Matrix-shaped sync responses with event bodies, invite/leave room
  categories, and top-level `presence`, `account_data`, `to_device`,
  `device_lists`, and `device_one_time_keys_count` stubs are implemented.
- E2EE key API foundation: upload/query/claim/cross-signing/signature/backup
  route shapes are runtime-wired with durable server-blind storage,
  one-time-key consumption, fallback-key reuse, backup rows, redaction, audit,
  and SQLite restart coverage.
- Inbound federation foundation: federation-only listener dispatch,
  inbound transaction scaffold, SSRF/TLS policy checks, duplicate handling,
  canonical JSON Ed25519 request verification, JSON PDU signature verification
  for known keys, signed-request integration coverage, inbound
  `GET /_matrix/key/v2/server` key publication, server discovery with
  `.well-known/matrix/server`, DNS SRV, A/AAAA, IPv6 pins, and private-address
  rejection, outbound transaction types, exponential backoff,
  circuit-breaker policy, `OutboundClient`, `perform_outbound_transaction`,
  and per-platform TLS outbound integration coverage exist.
- Media repository foundation: authenticated local upload/download, MIME
  policy, quarantine/release/remove, LibSodium digest, metrics, audit,
  metadata/blob persistence, sandbox/AV/decoder/decompression processing
  boundary, remote-ingest boundary, thumbnail metadata, and integration
  coverage exist.
- Database persistence: prepared-statement boundary, schema inventory,
  migration model, in-memory persistent store, SQLite RAII backend,
  current-schema bootstrap, fail-closed hydration, busy timeout, runtime
  hydration, write-through users/devices/tokens/rooms/events/E2EE
  keys/media/audit/admin rows, SQLite rollback coverage, PostgreSQL RAII
  connection/result boundary, PostgreSQL schema bootstrap/pending-migration
  hydration/write-through path, migration file loading, offline migrator
  scaffold, database role separation, durable trust-and-safety rows, policy
  rules, account data, federation queues, media blob rows, and
  restart-survival integration coverage exist.
- Observability and audit: structured logging, redaction-aware debug
  diagnostics across HTTP dispatch, client-server auth/routing, room joins,
  room events, event authorization, persistence, and federation decision paths,
  operator-facing `--debug` and `--log-file <path>` startup controls,
  health snapshots, safe metrics summaries, redaction helpers, durable audit
  events, admin health/metrics/audit runtime endpoints, and client-server audit
  persistence exist.
- Trust and safety: registration/account/invite/federation/media/report policy
  engine, runtime client event reporting, admin safety report listing/review,
  durable policy audit rows, and durable admin action rows exist.
- Packaging scaffolds: systemd, OpenRC, BSD rc.d, Docker assets, Debian control
  metadata, RPM spec metadata, and BSD package metadata exist for early
  deployment-shape testing.
- Distribution packaging: installable `.deb` (Debian/Ubuntu), `.rpm` (Fedora),
  and `.pkg` (FreeBSD) packages are produced by CI on every push. All three
  packages include a sample config file. Security libraries (OpenSSL, libsodium,
  libpq) link dynamically from OS packages so distro security updates (`apt
  upgrade`, `dnf upgrade`) patch them without rebuilding Merovingian; the `.deb`
  declares `libssl3`, `libsodium23`, and `libpq5` as runtime `Depends`.
  Application dependencies (libcurl, SQLite, yyjson) remain statically linked via
  source-pinned Meson wraps. CI also builds an Alpine/musl static Linux fallback
  tarball with `-static-pie` for older distributions that cannot easily consume
  the distro packages. Pushes to `main` replace the rolling GitHub `latest`
  prerelease through repo-scoped `gh release` commands so the artifact
  publication job does not retain stale release state.
- Test isolation: `registration_token_file()` now generates a process-unique
  filename (random salt + atomic counter) so parallel `meson test` jobs do not
  truncate each other's token file mid-write, eliminating intermittent 403
  failures in the rate-limit cross-user isolation test.
- Supply-chain automation: release publication, secret scanning, dependency
  vulnerability triage, and SBOM workflows exist and are checked by the
  release-readiness gate.
- Direct runtime dependencies resolve through committed source-pinned Meson
  wraps for libcurl, SQLite, Catch2, and yyjson. OpenSSL, LibSodium, and
  PostgreSQL libpq resolve from operating-system packages and explicitly
  disallow Meson fallback resolution so distro security updates apply to
  production builds. curl uses the `unstable-external_project` module to build
  from an upstream tarball via its native configure script. The shared make
  shim forwards Meson's staged `DESTDIR` as a make command-line variable so
  upstream Makefiles that assign `DESTDIR=` internally still install into the
  build-local external-project dist directory. The curl packagefile exposes
  curl's installed include root so `<curl/curl.h>` resolves on BSD. The curl
  fallback disables optional zlib and zstd support so its static archive does
  not need undeclared compression libraries at link time. The curl packagefile
  also passes `--disable-dependency-tracking` so automake's `depcomp` bootstrap
  does not fail on NTFS-backed filesystems (WSL builds under `/mnt/c/`). A
  dedicated `scripts/build-wsl.sh` wrapper defaults to `build-wsl`, detects
  stale curl subproject directories (including extracted source trees whose
  copied `meson.build` no longer matches
  `subprojects/packagefiles/curl/meson.build`, and build trees configured
  without `--disable-dependency-tracking`), wipes them automatically, and
  still re-extracts stale curl sources after `--clean` removes the build
  directory for a full rebuild. The wrapper also stages an executable
  Linux-filesystem `make` shim before Meson setup so `external_project`
  invocations do not fail on DrvFS execute-bit handling or CRLF shebangs. The
  Windows `build-wsl.cmd` and `scripts/build-wsl.ps1` launchers now delegate to
  that same wrapper so WSL builds keep the NTFS guardrails even when started
  from Windows. Catch2 fallback builds
  disable Catch2's own upstream SelfTest target; SQLite fallback builds are
  static so sanitizer jobs link sanitizer runtimes through Merovingian's test
  executables. Meson tests run with a default fallback-runtime setup that
  exposes staged curl external-project library directories through
  `LD_LIBRARY_PATH`, and the aggregate Catch2 unit-test binary has an explicit
  CI-sized timeout so fallback, coverage, and sanitizer jobs do not kill a
  passing suite at Meson's 30 second default. Post-build validation scripts that
  execute `merovingian-server` directly also expose those staged curl library
  directories before running dry-run checks. `_FORTIFY_SOURCE=3` is requested
  only for optimized builds so Fedora debug CI does not fail warnings-as-errors
  on glibc's optimization diagnostic. Fedora container CI now covers the Red Hat
  package family in addition to Ubuntu and FreeBSD. Current pinned wrap
  versions: curl 8.20.0, Catch2 v3.14.0, SQLite 3.53.1, yyjson 0.12.0.
- Client discovery: unauthenticated `GET /_matrix/client/versions` returns
  supported versions `v1.1` through `v1.18` with an empty `unstable_features`
  object.
- Response JSON: client-server responses use `canonicaljson::Value` and
  `serialize_canonical` instead of hand-rolled JSON string construction.
- Remote signing key cache: outbound `GET /_matrix/key/v2/server` fetch
  through the pinned `http::OutboundClient`, self-signature verification with
  libsodium for every listed verify key, persistence into
  `server_signing_keys` with `valid_until_ts`, refresh-on-rotation with a
  real wall-clock fallback, and an injectable
  `FederationRuntimeState::remote_key_resolver` that returns discovery-seeded
  remote runtime records for inbound request and PDU signature verification.
- Outbound dispatch worker: bounded queue with per-destination retry
  state, configurable max-retries/backoff, deterministic clock and
  resolver injectables, and a request_shutdown / drain / join lifecycle
  driving `perform_outbound_transaction`, honoring
  `destination_should_retry`, and requeueing circuit-open transactions for
  the destination retry deadline. Pending outbound transactions and destination
  retry state are persisted to `federation_transactions` and
  `federation_destinations`, then replayed into a restarted worker; shutdown
  leaves backoff-delayed rows durable for the next start. All
  `PersistentStore` mutations from the worker are serialised under the worker
  mutex, durable persistence failures on the retry/delivery paths are treated
  as hard failures rather than silent drops, and replay parks rows beyond
  `max_queue_depth` in an overflow buffer that drains into the active queue
  as in-flight work completes.
- Inbound PDU + EDU ingestion: canonical-JSON transaction body parser,
  PDU envelope extraction, `FederationRuntimeState::pdu_sink` and
  `edu_sink` hooks, classification and per-type content validation for
  `m.typing`, `m.receipt`, `m.presence`, `m.direct_to_device`, and
  `m.device_list_update`. PDU state conflicts now flow through a
  state-resolution v2 merge via `apply_state_resolution_v2` and a wired
  `state_conflict_resolver`; merged forks count as appended and audit as
  `federation.pdu_state_resolved`, while resolution failures retain the
  original `federation.pdu_state_conflict` audit.
- Federation membership and history endpoints: inbound `make_join`,
  `make_leave`, `make_knock`, `send_join` (v1 + v2), `send_leave`
  (v1 + v2), `send_knock`, `invite` (v1 + v2), and `backfill` are
  dispatched through typed runtime hooks
  (`membership_template_provider`, `membership_acceptor`,
  `invite_handler`, `backfill_provider`). Unwired endpoints respond
  `501 Not Implemented`. Outbound counterparts
  (`make_outbound_make_membership`, `make_outbound_send_membership`,
  `make_outbound_invite`, `make_outbound_backfill`) compose
  `OutboundTransaction` records carrying the spec-defined targets,
  query parameters, and v1/v2 invite body shapes.
- Sync v1.18 conformance: `GET /_matrix/client/v3/sync` now populates
  every documented top-level key. `presence.events`,
  `account_data.events` (global and per joined room),
  `to_device.events`, `device_lists.changed` / `.left`,
  `device_one_time_keys_count`, and `device_unused_fallback_key_types`
  read from the persistent store. Long polling blocks on a
  `SyncNotifier` until a sync-relevant `next_sync_stream_id` advance.
  The `filter` query parameter accepts inline JSON filters covering
  room include/exclude lists, timeline limit/sender/type predicates,
  and `include_leave`. Schema v7 (`sync_surfaces_tables`) adds the
  backing rows. `StreamToken` carries a third `sync_stream_id`
  segment so `next_batch` covers all surfaces. A Complement-style
  JSON fixture (`tests/fixtures/complement/sync_v1_18.json`) drives
  the spec shape end-to-end.
- Live PostgreSQL integration coverage with runtime/migration role
  enforcement: a dedicated GitHub Actions workflow
  (`.github/workflows/postgres-integration.yml`) starts a PostgreSQL 16
  service, provisions `merovingian_migration` (DDL) and
  `merovingian_runtime` (DML-only) roles via default privileges, and
  runs live integration scenarios that assert schema bootstrap reaches
  `current_schema_version`, persisted rows survive a close/reopen, and
  a runtime-role session is denied `CREATE TABLE`. The
  `PostgresqlConnection` API exposes `set_postgresql_role`,
  `reset_postgresql_role`, and `current_postgresql_user` so runtime
  callers can switch identities within a single connection; role names
  are validated against PostgreSQL identifier shape before being
  interpolated.
- Fuzz targets run in CI for canonical JSON and HTTP transport. A
  dedicated GitHub Actions workflow (`.github/workflows/fuzz.yml`)
  builds the harnesses with `-fsanitize=fuzzer,address,undefined` and
  runs each target for a bounded duration (120s per push, 900s on the
  Sunday scheduled run). `tests/fuzz/meson.build` enforces the
  libFuzzer flag set, and `scripts/run-fuzz-targets.sh` makes the same
  gate runnable locally. Findings, crash inputs, and corpora are
  uploaded as workflow artifacts.
- Fail-closed alpha hardening controls. `HardeningStatus::alpha_exception`
  and a `note` field replace the prior `unknown` placeholders in
  `run_startup_hardening_self_check`. `HardeningSelfCheck` exposes
  `production_blockers()`, `production_blocker_count()`,
  `is_production_ready()`, and `is_alpha_ready()`. `merovingian-server`
  refuses to start when any check reports `disabled`, logs
  alpha-exception checks at warning level with a documented note, and
  prints a `production_ready=…/alpha_ready=…` readiness summary. The
  deferred controls and their beta/production retirement plans are
  documented in `docs/hardening-alpha-exceptions.md`, which the
  release-readiness script requires.

### Beta

Beta means the homeserver has broad Matrix v1.18 behavior coverage, can survive
realistic operator testing, and can federate with selected remote homeservers in
a non-production environment.

#### TODO

- Promote remaining endpoint behavior from `partial` to `spec-covered` with
  conformance fixtures.
- Add live PostgreSQL integration tests that cover transaction rollback,
  migration ordering, and role-grant failures.
- Wire live media remote-fetch transport and server discovery into the
  repository remote-ingest boundary, then replace thumbnail metadata with real
  image resampling output.
- Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability.
- Add policy server transport integration, durable policy-rule management, and
  richer moderation workflows.
- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers.
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests.

#### DONE

- Alpha foundations listed above.
- Federation request signing and PDU signature verification boundaries exist for
  known keys.
- PostgreSQL schema bootstrap, hydration, write-through path, and database role
  separation scaffolding exist.
- Admin health, metrics, audit, media moderation, and trust-and-safety review
  routes exist.
- Matrix UI-Interactive Authentication for `POST /register`: absent `auth` field
  returns 401 with `m.login.registration_token` flow, `params`, and `session`.
- `POST /account/password` for authenticated password change with Argon2id
  hashing and persistent-store write-through.
- `PUT /profile/{userId}/displayname` and `PUT /profile/{userId}/avatar_url`
  with cross-user 403 protection.
- `GET /profile/{userId}` moved before the auth gate (unauthenticated per spec).
- Client-server v1.18 conformance fixture extended with profile negative cases,
  unknown-room state 403, and password-change coverage.
- Redaction-aware debug diagnostics are wired into room join, auth, HTTP,
  persistence, and federation paths, exposed through `--debug` and
  `--log-file <path>`, with operator notes in
  `docs/debug-logging.md`.
- X-Matrix Authorization header parsing: `parse_x_matrix_authorization_header`
  extracts `origin`, `destination`, `key_id`, and `sig` from inbound federation
  Authorization headers. TLS-bound origin validation rejects requests where
  `tls_peer_server_name` differs from `origin` with a 403 before any further
  processing. Unit coverage exists for valid, minimal, missing-field, malformed,
  and wrong-scheme inputs plus TLS match, empty, mismatch, and prefix cases.
- Federation runtime callbacks wired: `pdu_sink`, `state_conflict_resolver`,
  `membership_template_provider`, `membership_acceptor`, `invite_handler`,
  `backfill_provider`, and `remote_key_resolver` are lazily wired into
  `FederationRuntimeState` on the first inbound federation request.
  `pdu_sink` persists inbound PDUs through the persistent store.
  `state_conflict_resolver` runs state-resolution v2 via
  `apply_state_resolution_v2`. Membership hooks cover `make_join`,
  `make_leave`, `make_knock`, `send_join`, `send_leave`, `send_knock`, `invite`,
  and `backfill` from durable event rows. `remote_key_resolver` uses
  `make_persistent_remote_key_resolver` with a real wall-clock for discovered
  and rotation-triggered remote key fetch and cache. BDD coverage for all
  callbacks exists in `test_federation_runtime_callbacks.cpp`.
- PostgreSQL restart-survival coverage extended: integration tests assert that
  users, access tokens, rooms, memberships, events, account data, policy rules,
  federation destinations, federation transactions, local media, and remote media
  all survive a close/reopen cycle on a real PostgreSQL-backed persistent store.

### Production v1.0.0

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

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
- Enforce PostgreSQL transaction coverage, migration coverage, and role grants
  against real temporary databases.
- Fail closed when required production hardening controls are unavailable.
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- Add signed release artifacts, reproducible builds, dependency pinning
  policy, license review, provenance, and artifact signatures.
- Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and artifact signatures
  in release notes.

#### DONE

- Packaging files exist for Linux and BSD deployment-shape testing:
  `packaging/systemd/merovingian.service`, `packaging/openrc/merovingian`,
  `packaging/rc.d/merovingian`, and `Dockerfile`.
- Release-readiness script exists and rejects missing required release files or
  known unsafe legacy hashing primitives.
- Alpha prerelease publishing exists: `.github/workflows/release.yml` builds
  hardened Linux and FreeBSD tarballs for `v*-alpha*` tags, runs tests and
  release-readiness gates, emits SHA-256 checksum files, and publishes a
  GitHub prerelease.
- CodeQL, coverage, sanitizer, static-analysis, and Linux CI jobs install
  LibSodium development headers before configuring Meson.
- Federation request signing follows the Matrix-spec X-Matrix scheme: the
  signed payload is the canonical JSON object `{content?, destination, method,
  origin, uri}`, signed with the server's real Ed25519 secret key and verified
  against the remote's published `/_matrix/key/v2/server` public key. The prior
  shared-secret `verify_token` derivation — which could not interoperate with
  other homeservers — has been removed. PDU event signatures are verified via
  libsodium against known or on-demand-discovered keys; rotated keys trigger
  re-fetch through `make_persistent_remote_key_resolver` when `valid_until_ts`
  has passed or the `key_id` no longer matches, and the refreshed key is
  persisted before re-verification. Covered by unit and integration tests; a
  live interoperability test against an external homeserver remains outstanding.
- Runtime users, tokens, rooms, events, account data, policy rules, federation
  destinations, federation transactions, local media, and remote media survive
  restart for both SQLite and PostgreSQL backends, verified by integration tests
  covering close/reopen cycles on all persisted data types.

## Immediate priority order

With the Alpha gates closed, Beta priorities take over from here:

1. Complete Matrix v1.18 conformance for client-server endpoints currently
   marked `partial` — promote them to `covered` with conformance fixtures.
2. Add Matrix federation conformance fixtures covering join, leave, invite,
   backfill, and key-rotation scenarios end to end.
3. Retire one hardening alpha exception per minor release — start with the
   ELF program-header probe (linker hardening / RELRO) and Linux
   seccomp-bpf filter. Update `docs/hardening-alpha-exceptions.md` when an
   exception lands.
4. Wire live remote media transport/server-discovery into the new remote-ingest
   boundary and replace thumbnail metadata with real resampling output.
5. Promote CI from build/test checks to full capability gates with
   conformance, fuzzing (already gated), platform, packaging, and signed
   release evidence.

## Capability ledger

| Capability | Current status | Evidence | Gap |
| --- | --- | --- | --- |
| Build and warning policy | `runtime-wired` | Meson C++26 build, warnings-as-errors, hardening flags, Linux and FreeBSD CI, reusable local build wrappers, WSL bridge wrapper, and named debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Validated defaults, bounded parser, config-file metadata checks, reload planning, smoke tests | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | `net::TcpAcceptor` binds per `ListenerPlan`, `net::ShutdownSignal` handles SIGINT/SIGTERM, `homeserver::serve_http`/`serve_tls_http` accept/parse/dispatch loops, client listeners dispatch through the `client_server` Matrix JSON adapter, federation listeners dispatch through a federation-only router, default loopback federation bind avoids public reverse-proxy port `8448`, `--dry-run` flag for validation-only runs, integration tests exercising loopback HTTP and TLS round-trips | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, per-endpoint rate-limit enforcement keyed by normalized bucket, 429 `M_LIMIT_EXCEEDED` response on quota breach, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, libcurl-backed outbound HTTPS client with peer and hostname verification, redirects refused, https-only protocol, pinned-address DNS, bounded response cap, optional CA trust blob, and `MSG_NOSIGNAL` writes | Upgrade to `llhttp` or reviewed parser boundary, add request body streaming, keep-alive, HTTP/2, per-connection slowloris policy, remote-IP buckets for unauthenticated routes, durable rate-limit state, and operator-tunable policy overrides. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation, send, joined rooms, sync slices, unauthenticated `GET /_matrix/client/versions`, and Matrix v1.18-spec-complete sync response shape are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, conformance coverage, persistence semantics, and populate the top-level sync surfaces with real behavior. |
| Authentication and sessions | `runtime-wired` | LibSodium password hashing, CSPRNG access tokens, durable token hashes, SQLite/PostgreSQL hydration into runtime sessions, token-file-enforced public registration, UI-auth challenge for register (401 with flows/session when `auth` absent), explicit admin bootstrap API and startup flag, client-server register/login/logout/whoami/device/account-password routes, policy checks, durable audit events, and restart-survival coverage | Add richer operator bootstrap lifecycle controls, account recovery controls, and Matrix conformance fixtures for remaining auth flows. |
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, server-blind payload redaction, audit records, and SQLite restart coverage | Add Matrix device-list stream semantics, full key-count algorithms, complete backup version/session retrieval/deletion, Matrix v1.18 semantics, and conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | Strict canonical JSON parser boundary, deterministic serializer, event envelope, content hashes, reference-hash event IDs, redacted signing payloads, Base64 Ed25519 signature attachment/verification, persisted runtime signing key, signed runtime event JSON, durable event DAG rows, room-version-aware redaction, v6+ auth rules, state resolution v2, incremental sync with stream tokens and `since`, Matrix-shaped sync responses with `rooms.join`, `rooms.invite`, `rooms.leave`, and top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys, encrypted-room policy, local room flow, and restart-survival integration coverage | Add sync long polling and filters, real payloads for presence/device/to-device/account-data surfaces, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through a federation-only router, inbound transaction scaffold, unauthenticated inbound `GET /_matrix/key/v2/server` key publication with a canonical self-signed response, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known and discovered remote keys, X-Matrix header parsing via `parse_x_matrix_authorization_header`, TLS-bound origin validation, signed-request integration coverage, server discovery with HTTPS well-known fetch, DNS SRV, A/AAAA resolution, IPv6 pins, private/loopback rejection, remote key fetch/cache with every listed verify key self-signed and rotation-triggered refresh via `make_persistent_remote_key_resolver`, outbound transaction types with exponential backoff and circuit breaker policy, `merovingian::http::OutboundClient`, `perform_outbound_transaction` wiring, `DispatchWorker` bounded retry queue, durable queue/destination persistence with restart replay, X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, circuit-breaker short-circuit before network I/O, circuit-open requeue, inbound PDU/EDU ingestion hooks, all seven federation runtime callbacks wired (`pdu_sink`, `state_conflict_resolver`, `membership_template_provider`, `membership_acceptor`, `invite_handler`, `backfill_provider`, `remote_key_resolver`), and per-platform TLS integration coverage | Production runtime worker startup for outbound replay, room-version-specific PDU verification, key rotation publication, multiple active/old keys, and Matrix federation conformance coverage. |
| Media repository | `runtime-wired` | Runtime media routes for authenticated local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit, persistent metadata/blob writes, SQLite restart hydration, sandboxed processing worker boundary, AV hook boundary, decoder/decompression limits, remote-ingest boundary, thumbnail metadata, and integration coverage | Wire live remote media transport/server-discovery into the remote-ingest boundary, add real image thumbnail resampling, and carry true content headers through the local request model. |
| Database persistence | `runtime-wired` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/E2EE keys/media/audit/admin/account-data/federation-queue/policy-rule/media-blob rows, SQLite transaction rollback, atomic runtime helpers, dependency reviews, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/pending-migration hydration/write-through path, migration-file loading, offline migrator scaffold, database role separation, durable trust-and-safety rows, and restart-survival integration coverage | Add more live PostgreSQL integration tests and enforce runtime/migration grants through separate PostgreSQL users in deployment packaging. |
| Observability and audit | `runtime-wired` | Structured logging, health snapshots, safe metrics summaries, redaction helpers, durable audit events, admin health/metrics/audit runtime endpoints, and client-server action audit persistence | Add production scrape/export contract, log format contract, trace correlation, and operator docs. |
| Trust and safety | `runtime-wired` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes, runtime client event reporting, admin safety report listing/review, durable policy audit rows, and durable admin action rows | Add Matrix v1.18 conformance fixtures, policy server transport integration, durable policy-rule management, and richer moderation workflows. |
| Runtime hardening | `integrated` | Systemd/OpenRC/rc.d packaging, hardening plan, startup self-check with `HardeningStatus::alpha_exception` + documented notes, `merovingian-server` refusing to bind when any control reports `disabled`, alpha-only exceptions enumerated in `docs/hardening-alpha-exceptions.md`, and release-readiness gating on the new doc | Implement the in-process probes that retire each documented alpha exception: ELF program-header probe for linker/RELRO status, Linux seccomp-bpf filter, OpenBSD pledge/unveil, FreeBSD Capsicum, optional in-process privilege drop, Landlock confinement, and `RLIMIT_CORE` clamp. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `integrated` | Canonical JSON and HTTP fuzz targets build with `-fsanitize=fuzzer,address,undefined`, the `fuzz` GitHub Actions workflow runs each target for a bounded duration on every push (and longer on a Sunday schedule), and crash inputs/corpora are uploaded as artifacts | Add durable corpus management, broader Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `integrated` | Release-readiness script, installable `.deb`/`.rpm`/`.pkg` packages built by CI, Alpine/musl static Linux fallback tarball, tag-driven alpha prerelease workflow, SHA-256 checksums, alpha hardening exceptions documentation, plus dedicated secret-scan, dependency-vulnerability-triage, and SBOM workflows | Add dependency pinning policy, license review, artifact signing, provenance, and reproducible build notes. |

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
Federation listeners dispatch into a federation-only router that exposes only
federation requests and server-key publication. Internal compatibility paths can
still dispatch into the legacy local router until those surfaces have production
adapters.

### Client-server API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Authentication | `POST /_matrix/client/v3/register` | `spec-covered` | Matrix JSON body is parsed, registration-token UI auth is enforced from the configured token file. When the `auth` field is absent the server returns 401 with the `m.login.registration_token` flow, `params`, and a `session` token per Matrix UI-auth. Public registration creates non-admin users, local registration is reachable through the client listener, SQLite-backed local users survive restart, and happy-path and UI-auth challenge cases are covered by the v1.18 fixture. Needs PostgreSQL coverage. |
| Authentication | `GET`/`POST /_matrix/client/v3/login` | `partial` | Password login works for local users with LibSodium-backed hashes, token hashes are SQLite-persisted, GET login returns password-flow discovery, restart-survival is tested, and the v1.18 fixture covers password login with and without requested refresh-token support. Fixed: INSERT SQL for device and access-token rows was missing parentheses (broke all logins). Needs full Matrix login flows and PostgreSQL coverage. |
| Authentication | `POST /_matrix/client/v3/logout` | `spec-covered` | Local bearer-token logout works through the client listener, revokes the current token through the persistent store, and is covered by the v1.18 fixture with stale-token rejection. |
| Authentication | `POST /_matrix/client/v3/logout/all` | `spec-covered` | Runtime global logout revokes all user access and refresh tokens, marks active sessions revoked, appends durable auth audit, and is covered by the v1.18 client-server fixture. |
| Authentication | `POST /_matrix/client/v3/refresh` | `spec-covered` | Login issues a refresh token, `/refresh` rotates refresh/access tokens through persisted token hashes, revokes the old device access tokens, and is covered by the v1.18 client-server fixture with missing/reused refresh-token rejection. |
| Account | `GET /_matrix/client/v3/account/whoami` | `spec-covered` | Local token identity works through the client listener, is covered after SQLite restart, and is covered by the v1.18 fixture. |
| Account | `POST /_matrix/client/v3/account/password` | `spec-covered` | Authenticated password change validates the new value, hashes with Argon2id, and writes through to the in-memory runtime and the persistent store. Returns 401 without auth, 400 for weak passwords, and 200 on success. Covered by the v1.18 fixture and integration tests. Needs UI-auth re-authentication and `logout_devices` handling. |
| Devices | `GET /_matrix/client/v3/devices` | `spec-covered` | Device listing works through the client listener, is hydrated from SQLite devices, and is covered by the v1.18 client-server fixture. Needs Matrix device-list stream semantics. |
| Devices | `GET /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Runtime single-device fetch returns the Matrix device object or `M_NOT_FOUND` and is covered by the v1.18 client-server fixture. |
| Devices | `PUT /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Display-name update persists through the persistent store, updates the runtime mirror, appends durable audit, and is covered by the v1.18 client-server fixture with malformed-body rejection. |
| Devices | `DELETE /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Runtime deletion removes the device row, revokes that device's access and refresh tokens, marks active sessions revoked, appends durable audit, and is covered by the v1.18 client-server fixture. Needs full UI-auth delete-device fallback semantics. |
| Rooms | `POST /_matrix/client/v3/createRoom` | `partial` | Local room creation works through the client listener and SQLite-persisted rooms survive restart. Needs full create-room semantics, auth events, and conformance fixtures. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/join` | `partial` | Local join slice works through the client listener and membership writes route through the persistent store. Needs full membership rules and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/join/{roomIdOrAlias}` | `partial` | Join-by-id delegates to the same local join handler as `/rooms/{roomId}/join` by rewriting the request target. Needs room-alias resolution, the `?server_name` hint, and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` / `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `partial` | Local send slice works through the client listener with Matrix reference-hash event IDs, content hashes, persisted Ed25519 signatures, previous/auth event DAG rows, full v6+ auth checking against current room state before persistence, and a spec-shaped PUT send alias covered by the v1.18 fixture with malformed-content rejection. Needs idempotent transaction IDs, restricted join rule evaluation, third-party invite auth, and incremental sync completion. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` / `PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` | `partial` | Local state summary works through the client listener, state writes can arrive through the spec-shaped PUT state alias, and the path is covered by the v1.18 fixture with malformed-content rejection. Needs full state event retrieval and state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `partial` | Sync returns Matrix v1.18-shaped JSON with event bodies in timelines, stream-token-based `next_batch`, and incremental diffing when `since` is provided. `rooms.join`, `rooms.invite`, and `rooms.leave` are emitted from `PersistentMembership`; top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys are emitted with empty payloads. Needs populated payloads behind those keys, wiring the stored filter_id query parameter to filter application, long polling, presence updates, device-list change tracking, to-device messages, and durable stream tokens. |
| Sync | `POST /_matrix/client/v3/user/{userId}/filter` | `spec-covered` | Filter upload is runtime-wired through the client-server adapter, stores the filter JSON verbatim, returns an opaque `filter_id`, and is covered by the v1.18 fixture with cross-user rejection. Needs SQLite/PostgreSQL restart-survival coverage. |
| Sync | `GET /_matrix/client/v3/user/{userId}/filter/{filterId}` | `spec-covered` | Filter retrieval is runtime-wired, returns the stored filter JSON, and is covered by the v1.18 fixture with missing-filter rejection. Needs restart-survival coverage. |
| Account data | `PUT`/`GET /_matrix/client/v3/user/{userId}/account_data/{type}` | `spec-covered` | Global (non-room) account data is runtime-wired through the persistent store with an upsert, surfaces in `/sync`, and is covered by the v1.18 fixture with empty-body, missing-type, and cross-user rejection. Cinny stores `m.direct` here. Needs room-scoped account data (`/rooms/{roomId}/account_data/{type}`). |
| Discovery | `GET /_matrix/client/versions` | `spec-covered` | The unauthenticated spec discovery endpoint answers before the auth check with the versions array `v1.1` through `v1.18`, an empty `unstable_features` object, and v1.18 fixture coverage. Needs feature flags for unstable spec extensions once adopted. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `spec-covered` | Joined-room list works through the client listener, is hydrated from SQLite memberships, and is covered by the v1.18 fixture. Needs full access checks. |
| Media | `GET /_matrix/media/v3/config` | `spec-covered` | Returns `m.upload.size` from the configured `security.media.max_upload_size` value and is covered by the v1.18 fixture. Cinny fetches this after login to know the maximum attachment size. |
| Media | `POST /_matrix/media/v3/upload` | `spec-covered` | Local authenticated upload, MIME checks, quarantine, digest, sandbox/AV/decoder/decompression processing boundary, thumbnail metadata, metrics, audit, metadata/blob persistence, and client-server JSON `content_uri` response are runtime-wired and covered by the v1.18 fixture with unauthenticated and malformed upload rejection. Needs multipart/content handling through real HTTP. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `spec-covered` | Local download is reachable through the client-server adapter and covered by the v1.18 fixture with missing-media rejection. Remote ingest has a repository boundary but route-level live remote transport remains disabled/fail-closed. Needs real content headers once the local request model carries headers. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `spec-covered` | Authenticated event reports are runtime-wired through the client-server adapter, validated by the trust-and-safety policy engine, appended to durable policy audit rows, and covered by the v1.18 fixture with optional `reason`, ignored legacy `score`, and malformed-body rejection. Needs richer report storage/query semantics and joined-room membership enforcement. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `spec-covered` | Authenticated key API route shapes are runtime-wired through the client-server adapter with durable server-blind key storage, request-body-driven `/keys/query` and `/keys/claim`, one-time-key consumption, fallback-key reuse, backup rows, payload redaction, audit records, SQLite restart coverage, 64 KiB body limit, and v1.18 fixture coverage for upload/query/claim plus malformed upload/query/claim rejection. Needs Matrix device-list stream semantics, complete backup retrieval/deletion semantics, and full key-count behavior. |
| Capabilities/push rules | `GET /_matrix/client/v3/capabilities`, `GET /_matrix/client/v3/pushrules/` | `spec-covered` | Authenticated clients receive minimal stable capability and empty global push-rule responses, both covered by the v1.18 fixture. Needs real push-rule storage and richer capability negotiation. |
| Profile | `GET /_matrix/client/v3/profile/{userId}` | `spec-covered` | Unauthenticated endpoint served before the access-token gate. Returns the stored displayname and avatar_url for the user, or 404 M_NOT_FOUND for unknown users. Covered by the v1.18 fixture including unknown-user 404 and post-update retrieval. |
| Profile | `GET /_matrix/client/v3/profile/{userId}/{keyName}` | `spec-covered` | Unauthenticated `getProfileField`; returns only the requested field (`displayname` or `avatar_url`). An unset or unknown field returns 404 M_NOT_FOUND. Covered by the v1.18 fixture and integration tests. |
| Profile | `PUT /_matrix/client/v3/profile/{userId}/displayname` | `spec-covered` | Authenticated update; cross-user attempts return 403 M_FORBIDDEN. Body must be a JSON object with a `displayname` field. Covered by the v1.18 fixture and integration tests. |
| Profile | `PUT /_matrix/client/v3/profile/{userId}/avatar_url` | `spec-covered` | Authenticated update; cross-user attempts return 403 M_FORBIDDEN. Body must be a JSON object with an `avatar_url` field. Covered by integration tests. |
| Discovery | `GET /_matrix/client/unstable/org.matrix.msc2965/*` | `partial` | The whole MSC2965 OIDC discovery namespace (`auth_metadata`, `auth_issuer`) returns 404 M_UNRECOGNIZED before the access-token gate. Cinny probes these for OIDC support; 404 lets it fall back gracefully instead of producing a misleading 401. |
| VoIP | `GET /_matrix/client/v3/voip/turnServer` | `partial` | Returns an empty object and is covered by the v1.18 fixture. No TURN server is configured; an empty 200 lets clients disable VoIP gracefully. Needs real TURN credential issuance once VoIP is supported. |

### Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (inbound) | `partial` | Inbound transaction handling is runtime-wired through federation-only listener dispatch with request policy, duplicate handling, canonical JSON request-signature verification, JSON PDU event-signature verification for known and on-demand discovered keys with rotation-triggered refresh, X-Matrix header parsing, TLS-bound origin validation, PDU/EDU parsing, `pdu_sink` hook persisting PDUs to the durable store, `state_conflict_resolver` merging via state-resolution v2, and conflict audit. Needs richer EDU side effects, room-version-specific PDU verification, and conformance coverage. |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (outbound) | `partial` | `perform_outbound_transaction` composes the libcurl-backed `merovingian::http::OutboundClient` with X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, and circuit-breaker short-circuit through `destination_should_retry`. `DispatchWorker` provides a bounded retry queue, requeues circuit-open transactions for the destination retry deadline, persists pending rows and destination retry state, and replays pending rows after restart. Per-platform TLS integration coverage exercises valid round-trip, hostname mismatch, untrusted self-signed, and 3xx rejection. Needs production runtime wiring to start the replay worker and Matrix conformance coverage. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `integrated` | `make_join`, `make_leave`, `make_knock`, `send_join` (v1+v2), `send_leave` (v1+v2), `send_knock`, `invite` (v1+v2), and `backfill` are dispatched through runtime hooks: `membership_template_provider` builds the event template, `membership_acceptor` persists the event and returns auth-chain/state, `invite_handler` echoes back the invite JSON, and `backfill_provider` serves PDUs from durable rows. Unwired endpoints return 501. BDD callback coverage in `test_federation_runtime_callbacks.cpp`. Needs full Matrix conformance fixtures and production join/leave state semantics. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `partial` | Server discovery now fetches `https://<server>/.well-known/matrix/server` through the pinned outbound client, parses `m.server`, falls back to `_matrix-fed._tcp.<host>` SRV records, resolves A/AAAA addresses, handles public IPv6 pins, rejects private/loopback IPv4 and IPv6 addresses before exposing the pin set to `OutboundClient`, and feeds remote key fetch/cache for on-demand inbound verification. Needs TLS-bound origin validation, richer Matrix edge-case fixtures, and live network conformance coverage. |
| Signing verification | Request and event signatures | `partial` | Federation requests are signed and verified with the Matrix-spec X-Matrix scheme: the signed payload is the canonical JSON object `{content?, destination, method, origin, uri}`, signed with the server's real Ed25519 secret key and verified against the remote's published public key. The prior shared-secret `verify_token` derivation has been removed. JSON PDUs verify Matrix event signatures against known or on-demand-discovered remote keys; `make_persistent_remote_key_resolver` re-fetches when `valid_until_ts` has passed or the `key_id` no longer matches. Remote server-key responses must self-sign every listed verify key before caching. TLS-bound origin validation rejects requests where the TLS peer name differs from the X-Matrix origin. Needs room-version-specific PDU hash verification, a live interoperability test against an external homeserver, and conformance coverage. |
| Key publication | `GET /_matrix/key/v2/server` (inbound) | `partial` | The federation-only router answers unauthenticated key fetches with the persisted runtime Ed25519 verify key, `valid_until_ts`, empty `old_verify_keys`, and a canonical self-signature verified by integration coverage. Needs key rotation, multiple active/old keys, and Matrix federation conformance fixtures. |
| Federation queues | Outbound federation and retry/backoff | `partial` | `OutboundClient` is wired through `perform_outbound_transaction` with retry-state mutation via `apply_outbound_result`, circuit-breaker short-circuit via `destination_should_retry`, and a `DispatchWorker` that retries discovery and delivery failures without dropping circuit-open transactions. Pending transactions persist to `federation_transactions`, destination retry state persists to `federation_destinations`, and bounded worker replay hydrates both after restart. Needs production runtime worker startup and live federation delivery coverage. |

### Server administration and operations

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Health | `GET /_merovingian/admin/health` | `partial` | In-process admin health exists and is reachable over the TCP listener via the legacy local router. Needs a real admin auth model, JSON response shape, and deployment checks. |
| Media moderation | Quarantine, release, remove, metrics | `partial` | Admin media actions exist locally with durable state, audit, and metrics. Needs richer authorization model and operator docs. |
| Trust and safety review | Reports and admin review | `partial` | Admin safety report listing and review actions are runtime-wired through authenticated client-server routes with durable policy audit and admin action rows. Needs policy rule management, Matrix v1.18 fixtures, and policy server transport. |
| Metrics | Exported metrics | `partial` | Admin metrics summaries are runtime-wired and avoid secret fields. Needs production scrape/export contract and trace correlation. |
| Debug logging | Redaction-aware diagnostic summaries | `partial` | HTTP dispatch, client-server auth/routing, room joins/events, event auth, persistent-store writes, and federation decisions emit structured debug diagnostics. `merovingian-server --debug` enables console diagnostics and `--log-file <path>` writes file diagnostics. `docs/debug-logging.md` documents join-failure triage and the redaction boundary. Needs production log-format contract and request trace correlation IDs. |

## Completed capability notes

### Federation key publication and discovery

- `GET /_matrix/key/v2/server` returns a canonical Matrix server-key object
  backed by the runtime Ed25519 signing key persisted in the local store.
- The key response includes `server_name`, `valid_until_ts`, `verify_keys`,
  empty `old_verify_keys`, and a self-signature under `signatures`.
- Server discovery now uses an injectable network boundary for behavior tests
  and a system implementation for well-known fetches, DNS SRV lookup, and
  A/AAAA resolution.
- Address pins are rejected before outbound use when any resolved address is
  loopback, private IPv4, IPv4 link-local, IPv6 unique-local, IPv6 link-local,
  IPv6 loopback, or IPv4-mapped private/loopback.

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
git tag v<version>-alpha.1
git push origin v<version>-alpha.1
```

These commands are the minimum release evidence path. The release operator must
also record dependency versions, test logs, sanitizer logs, fuzz target names,
package checksums, and artifact signatures in release notes. Tags matching
`v*-alpha*` trigger `.github/workflows/release.yml`, which builds hardened
Linux and FreeBSD tarballs and publishes them as a GitHub prerelease, while
the published release event triggers `.github/workflows/sbom.yml` to attach
SPDX and CycloneDX inventories.
