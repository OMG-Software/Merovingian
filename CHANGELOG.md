# Changelog

## 0.1.21

- Marked the OpenSSL dependency include path as a system include so FreeBSD
  CI does not fail project warning-as-error gates on OpenSSL header macros.

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
