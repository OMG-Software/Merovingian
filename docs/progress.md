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
| Build and warning policy | `integrated` | Meson C++26 build, warnings-as-errors, hardening flags, Linux and FreeBSD CI | Add named build profiles for release, debug, sanitizers, fuzz, and hardened production. |
| Secure configuration | `runtime-wired` | Validated defaults, bounded parser, config-file metadata checks, reload planning, smoke tests | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | `net::TcpAcceptor` binds per `ListenerPlan`, `net::ShutdownSignal` handles SIGINT/SIGTERM, `homeserver::serve_http`/`serve_tls_http` accept/parse/dispatch loops, client listeners dispatch through the `client_server` Matrix JSON adapter, `--dry-run` flag for validation-only runs, integration tests exercising loopback HTTP and TLS round-trips | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, and `MSG_NOSIGNAL` writes | `llhttp` or reviewed parser boundary upgrade, request body streaming, keep-alive, HTTP/2, and runtime application of the slowloris policy. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation, send, joined rooms, and sync slices are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, add conformance coverage, and persist runtime state. |
| Authentication and sessions | `integrated` | LibSodium password hashing, CSPRNG access tokens, token hashes, policy checks, audit events | Add durable token/session storage, refresh-token rotation, registration tokens, admin bootstrap, and account recovery controls. |
| E2EE key APIs | `unit-covered` | Key API route/planning boundary exists | Implement upload/query/claim, fallback keys, device list updates, cross-signing, and key backup storage through runtime and persistence. |
| Rooms, events, and sync | `integrated` | `yyjson`-backed strict canonical JSON parser boundary, deterministic serializer, event envelope, redaction, state-resolution scaffold, encrypted-room policy, local room flow | Replace event ID/signature scaffolds with Matrix room-version-correct algorithms, full auth rules, event DAG persistence, and spec fixtures. |
| Federation | `integrated` | Route matching, inbound transaction scaffold, SSRF/TLS policy checks, trust-state logic | Implement real server discovery, TLS verification, canonical JSON signing, Ed25519 verification, joins/invites/backfill, and durable federation queues. |
| Media repository | `integrated` | Local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit | Add sandboxed processing worker, remote fetch, AV hook boundary, thumbnailing, decompression limits, and durable blob metadata. |
| Database persistence | `integrated` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/media/audit/admin rows, SQLite transaction rollback, atomic runtime helpers for device/token, room/membership, and event/current-state writes, libpq dependency review, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/hydration/write-through path, physical migration-file loading, offline migrator scaffold, database role separation, and restart-survival integration coverage | Add live PostgreSQL integration tests, enforce runtime/migration grants through separate PostgreSQL users, and full persistence for federation queues, account data, E2EE keys, policy rules, and media blob metadata. |
| Observability and audit | `integrated` | Structured logging, health snapshots, metrics, redaction helpers, audit events | Add durable audit log, metrics export endpoint, log format contract, trace correlation, and operator docs. |
| Trust and safety | `unit-covered` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes | Wire reporting/admin endpoints into runtime, persist policy actions, add Matrix v1.18 fixtures, and integrate policy server transport. |
| Runtime hardening | `scaffolded` | Systemd/OpenRC/rc.d packaging, hardening plan and self-check surfaces | Enforce fail-closed controls, implement seccomp/AppArmor/Landlock notes or profiles, OpenBSD pledge/unveil, FreeBSD Capsicum where practical. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `scaffolded` | Canonical JSON and HTTP fuzz targets can be built | Run fuzz targets in CI, add corpus management, Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `scaffolded` | Release-readiness script and packaging skeletons exist | Add SBOM, dependency pinning policy, license review, artifact signing, checksums, provenance, and reproducible build notes. |

## Immediate priority order

1. Add PostgreSQL/libpq persistence behind the SQLite-proven database boundary.
2. Replace federation and event signing scaffolds with Matrix canonical JSON
   and Ed25519 verification.
3. Keep `docs/protocol-coverage.md` up to date with every endpoint change.
4. Promote CI from build/test checks to capability gates with conformance,
   fuzzing, platform, packaging, and release evidence.
