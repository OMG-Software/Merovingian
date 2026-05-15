# Changelog

## 0.1.41

- Added outbound federation module: `OutboundTransaction` struct for tracking
  pending PDUs/EDUs to remote servers, `make_outbound_transaction` factory,
  exponential backoff with cap (`compute_backoff`), and circuit breaker retry
  policy (`destination_should_retry`).
- Added server discovery module: `ServerDiscoveryResult` for resolving server
  names, well-known delegation, and private IP rejection; `FederationDestination`
  struct for retry state persistence.
- BDD test coverage for outbound transaction creation, backoff computation,
  circuit breaker behavior, and server discovery validation.

## 0.1.40

- Added BDD test coverage for sync endpoint: initial sync returns stream
  token and event bodies; incremental sync with since token returns new
  events without duplicates.
- Sync route now uses starts_with to support query parameters.

## 0.1.39

- Added stream token type for incremental sync: encode/decode hex-based
  `event_ordering_membership_ordering` tokens that represent a position in the
  event stream.
- Added `sync` library with `StreamToken`, `encode_stream_token`,
  `decode_stream_token`, and `is_valid_stream_token` functions.
- Added `core::SyncRequest` and `core::parse_query_params` for extracting
  `since`, `timeout`, `full_state`, and `filter` from `/sync` query strings.
- Added `core::percent_decode` for URL percent-decoding sync filter values.
- Rewrote `sync_json` to produce Matrix v1.18-compliant sync responses with
  actual event bodies in timelines, stream-token-based `next_batch`, and
  incremental diffing when a `since` token is provided.
- Schema migration v5: added `stream_ordering` column to `events` and
  `membership` tables, `membership` column to `membership` table, and
  `event_id` + `stream_ordering` columns to `invites` table.
- Added `stream_ordering` field to `PersistentEvent` and `PersistentMembership`
  structs; `LocalDatabase` tracks `next_stream_ordering` for monotonically
  increasing event stream positions.
- Updated `store_event`, `store_event_with_state`, and `store_membership` to
  persist stream ordering and membership type.
- BDD test coverage for stream tokens, query parameter parsing, URL
  percent-decoding, and updated migration count assertions for v5.

## 0.1.38

- Fixed event authorization for room bootstrapping: the room creator is now
  implicitly treated as joined with power level 100 when no sender_member
  or power_levels event exists in the auth event map.
- Fixed self-join ban check: banned users are now correctly rejected by
  checking the target's membership rather than the sender's membership,
  resolving a false-allow when sender_member is absent but target_member
  records a ban.
- Fixed target_current_membership resolution for self-joins: when sender
  equals state_key, the sender_member is now used as the authoritative
  target membership if available.
- Made event auth check conditional on the presence of a create event in
  room state, allowing the simplified room creation flow to send events
  without auth rejection before a formal m.room.create state event exists.
- Added `effective_sender_power` helper to compute sender power level with
  creator-default-100 fallback when no power_levels event exists.

## 0.1.37

- Implemented full Matrix v6+ event authorization rules (14-step algorithm
  per spec section 10): create event validation, sender-domain matching,
  member join/invite/leave/ban with join-rule and power-level checks,
  power-level elevation guard, state-default and events-default enforcement,
  and redact power checks.
- Implemented v2 state resolution algorithm: conflicted/unconflicted state
  partition, reverse topological power sort, mainline ordering for
  power-level event ties, and iterative auth-based conflict resolution.
- Added `AuthEventMap` for building auth event context from current room state.
- Wired auth checking into the event sending path: composed events are
  authorized against current room state before persistence.
- Added helper functions for power-level extraction, membership state parsing,
  sender domain extraction, and content membership reading.
- Added `MembershipState::ban` to the membership state enum.
- Added comprehensive BDD test coverage for auth rule steps, join rules,
  power levels, kick/ban/invite flows, and v2 state resolution conflict
  scenarios.

## 0.1.36

- Replaced deterministic signing-key derivation with cryptographically random
  Ed25519 keypair generation so the runtime signing secret cannot be
  reconstructed from public server identity values (P1 fix).
- Required full Ed25519 event-signature verification for all PDUs when a
  signing key is available; comma-delimited PDUs without JSON are now
  rejected rather than bypassing cryptographic verification (P1 fix).
- Fixed `origin_server_ts` to use wall-clock Unix-epoch milliseconds
  instead of the sequential depth counter, conforming to the Matrix
  specification (P2 fix).
- Added `depth` column to the `events` table so event depth survives
  server restarts instead of regressing to zero (P2 fix).
- Extended `server_signing_keys` with a `server_name` column and composite
  primary key so key lookups are scoped to server identity, preventing
  cross-server key confusion after a `server_name` change (P2 fix).
- Added schema version `4` migration for the new `depth` and `server_name`
  columns and updated SQLite/PostgreSQL hydration and bootstrap.
- Added BDD coverage for random signing keys, depth persistence,
  server-scoped key lookups, comma-delimited PDU rejection, and
  wall-clock `origin_server_ts`.

## 0.1.35

- Removed the tracked `subprojects/yyjson` gitlink so CI and local clean
  checkouts use the pinned `yyjson.wrap` fallback plus the project-owned Meson
  package file.
- Ignored Meson-downloaded yyjson subproject checkouts and Python bytecode
  caches to keep generated dependency artifacts out of commits.
- Aligned CLI version output with the Meson project version for CI smoke tests.

## 0.1.34

- Runtime-wired authentication/session audit durability, admin metrics/audit
  summaries, and trust-and-safety report/review routes through the
  client-server runtime.
- Added named Linux/BSD/WSL build profiles for debug, release, sanitizer,
  coverage, fuzz, and hardened builds.
- Promoted authentication and sessions, database persistence, observability and
  audit, trust and safety, and build/warning policy to `runtime-wired` in the
  progress ledger with remaining production gaps documented.

## 0.1.33

- Fixed runtime state-event materialization so Matrix state events are detected
  by the presence of `state_key`, including the valid empty-string state key.

## 0.1.32

- Moved dependency reviews into `docs/dependencies/` and added reviews for
  LibSodium, OpenSSL, SQLite, yyjson, and Catch2 alongside PostgreSQL libpq.
- Added release-readiness checks for the dependency-review documentation set.

## 0.1.31

- Routed Linux, sanitizer, coverage, static-analysis, CodeQL, and FreeBSD CI
  builds through reusable local build wrappers.
- Added a FreeBSD build wrapper and Ubuntu/Debian WSL setup script that installs
  the native dependencies plus a current Meson/Ninja virtualenv.

## 0.1.30

- Fixed federation inbound-request compilation under CI warning-as-error builds
  by naming the intentionally unused request-signing key ID parameter,
  constructing owned signing-key IDs, and including the event-ID API.

## 0.1.29

- Confirmed OpenSSL as the TLS provider behind Merovingian's project-owned TLS
  boundary and kept the pinned WrapDB fallback for bootstrap builds.
- Clarified that GnuTLS is not the active replacement path while WrapDB lacks a
  standard `gnutls` package for this project to consume.

## 0.1.28

- Added a pinned OpenSSL WrapDB fallback so TLS builds no longer require a
  system OpenSSL package when Meson fallback downloads are enabled.
- Documented the GnuTLS tradeoff: it can be considered as a TLS provider, but
  there is no standard WrapDB `gnutls` package to consume directly.

## 0.1.27

- Wired runtime-created room events through persisted server signing keys, Matrix
  content/reference hashes, Ed25519 signatures, and reference-hash event IDs.
- Persisted local event DAG rows for previous events, auth events, and event
  signatures during runtime event writes, with SQLite/PostgreSQL hydration.
- Replaced federation request-signature scaffolding with canonical JSON
  Ed25519 verification and added JSON PDU event-signature verification for
  known remote signing keys.

## 0.1.26

- Replaced event ID scaffolding with Matrix reference-hash event IDs for modern
  room versions using SHA-256 and URL-safe unpadded Base64.
- Added Matrix content-hash calculation that excludes `unsigned`, `signatures`,
  and `hashes` before canonical JSON hashing.
- Redacted events before signing, stored Ed25519 signatures as Matrix unpadded
  Base64, and added verification against the signed canonical payload.

## 0.1.25

- Added schema version `3` for durable E2EE key storage tables covering device
  keys, key signatures, key backup versions, and key backup sessions.
- Added persistent-store helpers and SQLite/PostgreSQL hydration for device
  keys, one-time keys, fallback keys, cross-signing keys, signatures, key
  backup versions, and key backup sessions.
- Wired `/keys/upload`, `/keys/query`, and `/keys/claim` to persisted
  server-blind key state, including one-time-key consumption and fallback-key
  reuse after restart.
- Aligned executable version banners with the Meson project version and kept
  migration-plan validation coverage independent from current-schema coverage.

## 0.1.24

- Runtime-wired authenticated E2EE key API route handling through the
  client-server Matrix JSON adapter while keeping uploaded key payloads
  server-blind and redacted from runtime records/audit summaries.
- Promoted the progress ledger for E2EE key APIs, rooms/events/sync,
  federation, and the media repository to `runtime-wired` with current
  production gaps documented.
- Updated Matrix protocol coverage notes for the newly wired key API route
  slice and existing runtime wiring evidence.

## 0.1.23

- Resolved the PostgreSQL persistence branch merge with the SQLite transaction
  hardening already on `main`.
- Marked `libpq` headers as system includes and installed PostgreSQL client
  development packages in CI workflows.
- Made the database executor base movable so the RAII PostgreSQL connection can
  be returned by value without deleting its move operations.

## 0.1.22

- Wired PostgreSQL persistent-store bootstrap and row hydration behind the
  `libpq` boundary when a PostgreSQL URI file is explicitly configured.
- Added write-through PostgreSQL transaction execution for persistent-store
  mutations.
- Added physical SQL migration file loading and an offline
  `merovingian-db-migrate` planning scaffold.
- Added database runtime/migration role separation through `database.role`.
- Added explicit PostgreSQL integration-test gating through
  `MEROVINGIAN_TEST_POSTGRESQL_URI`.

## 0.1.21

- Marked the OpenSSL dependency include path as a system include so FreeBSD
  CI does not fail project warning-as-error gates on OpenSSL header macros.
- Added a reviewed `libpq` dependency boundary for PostgreSQL support.
- Added PostgreSQL connection-string policy and redacted connection summaries
  so password material is not exposed in diagnostics.
- Added RAII wrappers for PostgreSQL connections and command results using
  `PQfinish` and `PQclear`.
- Added parameterized PostgreSQL statement execution through `PQexecParams`
  behind the existing prepared-statement validation boundary.

## 0.1.20

- Added persistent-store transaction helpers so login device/token writes, room
  creation membership writes, and event/current-state writes commit atomically.
- Added SQLite backend transaction rollback coverage for failed statement
  groups.
- Changed SQLite startup hydration to fail closed when row queries cannot be
  prepared or stepped to completion.
- Set a busy timeout on SQLite connections and removed the FreeBSD
  warning-as-error failure caused by the `SQLITE_TRANSIENT` macro cast.

## 0.1.19

- Added an SQLite-backed persistent store with RAII connection/statement
  wrappers, current-schema bootstrap for new database files, row hydration at
  startup, and write-through persistence behind the existing database boundary.
- Hydrated runtime users, sessions, rooms, memberships, events, and client
  device listings from persisted SQLite rows when the homeserver restarts.
- Added integration coverage proving a SQLite-backed runtime can register,
  login, create a room, send an event, restart, authenticate the old token, and
  expose the persisted room state.
- Changed auth and room runtime mutations to fail the operation when the
  backing persistent store rejects required writes.
- Fixed the unsafe source gate regex literals so CI rejects banned allocation
  APIs instead of treating malformed grep patterns as success.

## 0.1.18

- Added an OpenSSL-backed TLS server boundary with RAII context and connection
  wrappers, handshake timeouts, TLS 1.2 minimum protocol enforcement, and
  fail-closed certificate/key loading.
- Wired TLS listener plans into the runtime accept loop so `listeners.*.tls=true`
  can serve the existing HTTP Matrix JSON adapter instead of being rejected at
  startup.
- Added listener TLS certificate/private-key configuration keys, validation,
  reload planning, secure file metadata checks, and loopback TLS integration
  coverage.

## 0.1.17

- Marked the pinned `yyjson` fallback include directory as a system include so
  project warning-as-error policy does not fail CI on third-party C header
  implementation details.
- Moved direct `yyjson.h` inclusion behind a C adapter so C++ static analysis
  does not parse third-party C inline implementation details.
- Updated the server version smoke test to assert `meson.project_version()`
  instead of a stale literal.
- Bounded clang-tidy CI to changed translation units with parallel per-file log
  groups and timeouts; headers remain covered transitively through compile
  commands.

## 0.1.16

- Added `yyjson` as the strict JSON parser dependency with a pinned Meson wrap
  fallback.
- Replaced the hand-written canonical JSON parser with a `yyjson` adapter that
  copies into the project-owned `canonicaljson::Value` model.
- Kept Matrix canonical JSON policy in Merovingian by rejecting duplicate keys,
  floats, exponent numbers, and unsigned values outside the signed 64-bit range
  during adapter conversion.

## 0.1.15

- Routed client listener traffic through the Matrix JSON client-server adapter
  while preserving local-router dispatch for federation/internal compatibility
  paths.
- Added loopback integration coverage proving TCP listener registration accepts
  Matrix JSON request bodies.
- Updated progress, protocol coverage, HTTP transport, and production-readiness
  docs for the client-listener dispatch change.

## 0.1.14

- Wired the `merovingian-server` binary to actually serve traffic: it now opens TCP listeners for the configured client (and federation, when enabled) binds, accepts HTTP/1.1 connections, parses request heads through the existing transport limits, and dispatches them to the local HTTP router.
- Added `merovingian::net::TcpAcceptor` (RAII TCP listening socket via `getaddrinfo`, `SO_REUSEADDR`, `IPV6_V6ONLY`, `getsockname`-reported bound port) and `merovingian::net::ShutdownSignal` (signal-safe self-pipe + SIGINT/SIGTERM handler installer; pinned to its construction site because the registered handler holds its address).
- Added `merovingian::homeserver::serve_http`, a single-threaded-per-acceptor accept/parse/dispatch loop that serialises shared runtime mutation through a caller-provided mutex and respects the existing `http::RequestLimits`.
- Added a `--dry-run` CLI flag that runs config validation and prints the startup summary without binding any listeners; previous smoke tests now opt in via `--dry-run`.
- TLS listeners (`tls=true`) fail closed at startup with a "TLS not yet implemented" error until the crypto stack is in place.
- New exit codes `runtime_start_error` (80) and `listener_error` (81) for failures after configuration validation.
- New BDD coverage: `test_tcp_acceptor`, `test_shutdown_signal`, and `test_http_server_listener_flow` (end-to-end loopback HTTP exchange against a started runtime).

## 0.1.13

- Added authoritative capability progress tracking and Matrix v1.18 protocol
  coverage documents.
- Marked numbered phase and milestone documents as historical tracking notes.
- Updated CI artifact and release-readiness checks to require the current
  progress documents.

## 0.1.12

- Update release readiness and CI artifact paths after numbering the
  production-readiness document.
- Remove clang-tidy-blocked `reinterpret_cast` calls from token and media
  digest input handling.

## 0.1.11

- Install LibSodium development headers in CodeQL and coverage CI jobs.
- Remove the legacy `token-hash:v1` marker from production persistence
  validation and align persistence tests on the current `token-hash:v2`
  format.

## 0.1.10

- Keep the smoke-test secure example config command as a single Meson
  expression for compatibility with the Meson version shipped by Ubuntu 24.04.

## 0.1.9

- Normalize repository shell scripts to LF and enforce shell-script line endings
  for WSL builds.
- Move permission-sensitive smoke-test fixtures into a Linux temporary
  directory so `/mnt/c` metadata does not block Unix mode checks.

## 0.1.8

- Run source-gate shell scripts through `sh` in Meson tests so WSL `/mnt/c`
  builds do not depend on executable bits or direct shebang execution.

## 0.1.7

- Suppressed Clang 22's `-Wc2y-extensions` diagnostic so Catch2 `__COUNTER__`
  test-registration macros do not fail `-Werror` builds.

## 0.1.6

- Added Linux and WSL build wrapper scripts for repeatable Clang 22 Meson builds.
- Added smoke coverage for the Linux build wrapper help and dry-run paths.
- Documented the WSL build workflow and Catch2 wrap fallback behavior.

## 0.1.5

- Promoted the client-server runtime API to production-named headers, source files, and entry points.
- Removed the old MVP-named client-server public symbols from the primary API surface.
- Added BDD coverage for the production-named client-server start and flow APIs.

## 0.1.4

- Replaced client-server registration, password login, and device update pipe bodies with parsed Matrix JSON request bodies.
- Added a single-request HTTP/1.1 adapter for the client-server facade with bearer-token extraction and exact body-length enforcement.
- Added fail-closed Matrix `M_BAD_JSON` coverage for malformed and incomplete client-server auth requests.
- Documented the remaining client-server production-readiness gap: the socket accept/read/write loop still needs to call the HTTP adapter.

## 0.1.3

- Replaced local homeserver password and access-token hashing with LibSodium-backed Argon2id/CSPRNG/generic-hash handling.
- Replaced the custom media SHA-256 implementation with LibSodium generic hashing for deduplication digests.
- Added Linux, OpenRC, BSD rc.d, and container packaging skeletons with production hardening defaults.
- Added release-readiness and security-review documentation plus a CI release metadata gate.
- Added BDD coverage for hardened local auth hash and token behavior.

## 0.1.2

- Preserved media repository and admin HTTP status codes through local homeserver routes.
- Added regression coverage for unauthenticated media uploads, admin media misses, quarantined downloads, remote media rejection, and zero-reference blob reupload.
- Documented the media repository status, digest, audit, and schema migration behavior.

## 0.1.1

- Added a Linux/BSD developer environment setup script with dry-run, check-only, package-manager override, and Meson build-directory configuration support.
- Documented the developer environment workflow and linked it from the README.
- Added smoke coverage for Linux, FreeBSD, OpenBSD, and NetBSD setup command planning.

## 0.1.0

- Initial secure bootstrap implementation with Meson build, configuration validation, runtime summaries, and security-focused test scaffolding.
