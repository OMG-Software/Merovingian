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
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, server-blind payload redaction, audit records, and SQLite restart coverage | Add Matrix device-list stream semantics, full key-count algorithms, complete backup version/session retrieval/deletion, Matrix v1.18 semantics, and conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | `yyjson`-backed strict canonical JSON parser boundary, deterministic serializer, event envelope, Matrix content hashes, reference-hash event IDs, redacted canonical signing payloads, Matrix Base64 Ed25519 signature attachment/verification boundary, persisted runtime signing key, signed runtime event JSON, durable previous/auth/signature event DAG rows, room-version-aware redaction, state-resolution scaffold, encrypted-room policy, local room flow, client listener dispatch for create/join/send/state/joined_rooms/sync, and restart-survival integration coverage | Complete auth rules, full state resolution, incremental sync streams, and broader Matrix v1.18 room-version fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through the local router, inbound transaction scaffold, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known remote keys, and signed-request integration coverage | Implement real server discovery, TLS verification against remote origins, joins/invites/backfill, event ingestion, and durable federation queues. |
| Media repository | `runtime-wired` | Runtime media routes for authenticated local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit, persistent metadata writes, and integration coverage | Add sandboxed processing worker, remote fetch, AV hook boundary, thumbnailing, decompression limits, and durable blob storage. |
| Database persistence | `integrated` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/E2EE keys/media/audit/admin rows, SQLite transaction rollback, atomic runtime helpers for device/token, room/membership, event/current-state, and key writes, dependency reviews under `docs/dependencies/`, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/hydration/write-through path, physical migration-file loading, offline migrator scaffold, database role separation, and restart-survival integration coverage | Add live PostgreSQL integration tests, enforce runtime/migration grants through separate PostgreSQL users, and full persistence for federation queues, account data, policy rules, and media blob metadata. |
| Observability and audit | `integrated` | Structured logging, health snapshots, metrics, redaction helpers, audit events | Add durable audit log, metrics export endpoint, log format contract, trace correlation, and operator docs. |
| Trust and safety | `unit-covered` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes | Wire reporting/admin endpoints into runtime, persist policy actions, add Matrix v1.18 fixtures, and integrate policy server transport. |
| Runtime hardening | `scaffolded` | Systemd/OpenRC/rc.d packaging, hardening plan and self-check surfaces | Enforce fail-closed controls, implement seccomp/AppArmor/Landlock notes or profiles, OpenBSD pledge/unveil, FreeBSD Capsicum where practical. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `scaffolded` | Canonical JSON and HTTP fuzz targets can be built | Run fuzz targets in CI, add corpus management, Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `scaffolded` | Release-readiness script and packaging skeletons exist | Add SBOM, dependency pinning policy, license review, artifact signing, checksums, provenance, and reproducible build notes. |

## Immediate priority order

1. Add live PostgreSQL integration coverage and runtime/migration role grants.
2. Complete Matrix event auth, auth-event selection, and state resolution.
3. Keep `docs/protocol-coverage.md` up to date with every endpoint change.
4. Promote CI from build/test checks to capability gates with conformance,
   fuzzing, platform, packaging, and release evidence.
