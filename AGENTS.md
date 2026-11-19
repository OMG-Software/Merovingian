## Project Overview
A Matrix homeserver built with security as the top priority: secure by design, in implementation, and at runtime.

## Language & Stack
- C++26
- LibSodium
- PostgreSQL
- SQLite
- Meson build system

## Required Coding Guidance

Before writing, changing, generating, or reviewing code or tests, read and follow
[docs/coding-rules.md](docs/coding-rules.md). Its requirements are binding for
all contributors and delegated agents; the link is not optional background reading.
Follow the security and testing guidance it references, together with the relevant
directory `AGENTS.md` files.

Keep project-wide coding rules in `docs/coding-rules.md`, not in this file.
Before reporting code work complete, check the change against those rules and
report any unresolved conflict or unmet requirement. See
[ADR-0465](docs/adr/0465-root-agent-guidance-requires-the-coding-rules-without-copying-them.md).

## General Workflow

- If something is ambiguous, ask clarifying questions, never assume.
- Flag potential bugs or edge cases after the code explanation if relevant.
- With every change, update the relevant docs. See [docs/AGENTS.md](docs/AGENTS.md) for the update table.
- Before creating a new branch from main, pull from origin so that main is up to date.
- Never change the version number unless the owner asks for it; a new branch keeps its base's version, and its
  CHANGELOG bullets go in the newest version's entry. See the [bump policy](docs/versioning.md#bump-policy) and
  [ADR-0835](docs/adr/0835-the-version-changes-only-when-the-owner-asks.md).
- Update the docs when code change invalidates something.
- Record a decision in the ADR register (`docs/adr/`) whenever you make one. A
  decision qualifies when a future reader would otherwise be likely to undo it
  by accident: a constraint the code depends on but does not state locally, a
  rejected alternative that looks better in isolation, or a rule about how to
  write future code. A choice with no rejected alternative is a fact, not a
  decision, and anything the Matrix spec mandates is not a decision either.
  Copy `docs/adr/template.md`, number it next (above every existing number;
  gaps from branches that never landed are allowed, but a number is never
  reused and nothing may cite a number that has no file), fill in status and
  date (both mandatory), and add a line to `docs/adr/index.md` in the same
  commit. Never renumber or delete an entry — mark it superseded. See
  [ADR-0000](docs/adr/0000-record-architecture-decisions.md),
  [ADR-0001](docs/adr/0001-use-markdown-architectural-decision-records.md) and
  [ADR-0543](docs/adr/0543-adr-numbers-are-assigned-in-order-gaps-are-allowed-and-a-number-is-never-reused.md).
- Record changes for each version in CHANGELOG.md, which starts at 1.0.0. `CHANGELOG-pre-release.md` holds the 0.x
  entries and is never added to ([ADR-0740](docs/adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).
  Each version is `# Version x.y.z` with `## Features`, `## Security Fixes`, `## Bug fixes` and `## Release notes`;
  see the [changelog format](docs/versioning.md#changelog-format).
- Ignore `.clwb` folder.
- Ignore directories starting with `build` in the project root (Meson build output).
- Always work in feature or bug branches, never main.
- Make the correct change for the ask, not the smallest.
- Update `CHANGELOG.md` on every change.

## Ignore list
Ignore these dirs:
- .claude/
- .github/
- .idea/
- .pytest_cache/
- .vscode/
- .worktrees/
- build/
- buildDir/
- build-*/

## Project Layout
Source headers (`include/merovingian/`) and implementations (`src/`) mirror each other by module and file name.
Some headers have no `.cpp` (header-only types, such as all of `bootstrap/`), and five sources in module directories have no header of
the same name in `include/`: `src/appservice/RegistrationYaml.cpp`, `src/database/SqliteStore.cpp`,
`src/federation_worker/WorkerEventLoop.cpp` (its header, `WorkerEventLoop.hpp`, sits beside it in `src/`),
`src/federation_worker/main.cpp`, and `src/media/thumbnail_worker_main.cpp`. The top-level `src/main.cpp` and
`src/db_migrate.cpp` are the other two executables' entry points.

```
├── include/merovingian/   # Public headers (same module dirs as src/)
│   ├── appservice/        #   Application Service registration, namespaces, outbound client
│   ├── auth/              #   Password hashing, session tokens, identity, key API
│   ├── bootstrap/         #   Process exit codes (header-only)
│   ├── canonicaljson/     #   Canonical JSON (value, parser, serializer, signable)
│   ├── config/            #   Config model, parser, runtime config, reload plan/policy
│   ├── core/              #   Error, FileDescriptor, SocketHandle, not_null, QueryParams, SecretBuffer
│   ├── crypto/            #   Ed25519, signing service, secret box, master key, IPC cipher, constant-time ops
│   ├── database/          #   Connection, statement, frozen v1 schema definitions, migrations, persistent_store, postgresql/sqlite
│   ├── email/             #   SMTP client (libcurl), mailbox-address and relay-URL checks, notification email
│   ├── events/            #   Event, event_id, event_signer, authorization, state_resolution, redaction, limits
│   ├── federation/        #   Inbound/outbound, transactions, key cache/query, server_discovery, membership, ACLs
│   ├── federation_worker/ #   Out-of-process federation worker (argument parsing; entry point in src/)
│   ├── homeserver/        #   Runtime, client-server dispatch, local router, federation proxy, worker supervisor, TLS
│   ├── http/              #   HTTP server, request, request limits, rate_limit, connection_guard, keep-alive, outbound client
│   ├── identity/          #   Identity Service API client (outbound only)
│   ├── ipc/               #   Authenticated, encrypted AF_UNIX channel between main process and federation worker
│   ├── media/             #   Media repository, MIME/quarantine security, sandboxed thumbnailer
│   ├── net/               #   Listener, TCP acceptor, thread pool, shutdown signal
│   ├── oauth/             #   OAuth 2.0 API: PKCE, scope, URI reader, redirect URI and client metadata rules, page renderer, base URL, server metadata, hand-off allowlist
│   ├── observability/     #   Logger, observability
│   ├── platform/          #   Runtime hardening, seccomp, ELF probe, file metadata, self-check
│   ├── push/              #   Push rules evaluation, push gateway client
│   ├── rooms/             #   Room version policy, encryption policy
│   ├── sync/              #   Sync filter, notifier, stream token, device-list deltas, sliding sync (MSC4186)
│   └── trust_safety/      #   Policy engine, ignore list
├── src/                   # Implementations (same module dirs as include/), plus the executables' main files
├── tests/
│   ├── conformance/       #   Catch2 BDD Matrix spec conformance tests
│   ├── unit/              #   Catch2 BDD unit tests (test_*.cpp)
│   ├── integration/       #   Flow/integration tests (test_*_flow.cpp)
│   ├── fuzz/              #   Fuzz targets
│   ├── smoke/             #   Smoke tests
│   ├── password_cost/     #   Proves the production Argon2id cost, in a binary without the tests' cheap hash
│   ├── complement/        #   Docker image that runs the release package under Complement
│   ├── fixtures/          #   Test fixtures: complement/ (JSON flow fixtures) and upgrade/ (the 1.0.3 release's SQLite database, PostgreSQL dump and manifest)
│   ├── support/           #   Test helpers (JsonTestSupport, MasterKey, RegistrationToken, TempDirectory, TlsMockServer)
│   ├── sanitizer/         #   Sanitizer suppression files (tsan.supp)
│   └── tooling/           #   Python tests for CI workflows, dependency wraps, example config, logger filter
├── migrations/            #   Numbered SQL migrations (001_*.sql …)
├── docs/                  #   All project docs (see list below)
├── scripts/               #   Build, format, lint, dev-setup scripts
├── packaging/             #   OS packages: deb, rpm, rhel, opensuse, freebsd, netbsd, openbsd; systemd, openrc, rc.d; postgresql role SQL
├── security/              #   Security coding rules
├── config/                #   Runtime config examples
├── subprojects/           #   Meson wrap dependencies
├── meson.build            #   Root build definition
├── meson.options           #   Build options
├── mkdocs.yml             #   Documentation site (GitHub Pages); hooks in scripts/mkdocs_site_hooks.py
└── build.py               #   Unified build CLI (Linux, BSD, WSL, remote Linux or BSD VM)
```

### Key entry points
- `src/main.cpp` — `merovingian-server` entry point: config, database, listeners, hardening, runtime start-up
- `src/db_migrate.cpp` — `merovingian-db-migrate` entry point: offline schema migration
- `src/federation_worker/main.cpp` — `merovingian-fed-worker` entry point: the sandboxed federation worker process
- `src/media/thumbnail_worker_main.cpp` — `merovingian-thumbnail-worker` entry point: the sandboxed image decoder (built only when libpng and libturbojpeg are found)
- `include/merovingian/homeserver/HomeserverRuntime.hpp` — `HomeserverRuntime`, the runtime state manager
- `include/merovingian/homeserver/ClientServerRuntime.hpp` — Client-Server API dispatch

### Key docs
`architecture.md` · `adr/index.md` · `coding-rules.md` · `security-coding-rules.md` · `testing-standards.md` · `versioning.md` · `threat-model.md` · `security-review-checklist.md` · `crypto-boundary.md` · `database-persistence.md` · `user-manual.md` · `auth-identity.md` · `event-engine.md` · `http-transport.md` · `media-repository.md` · `dev-environment.md` · `platform-support.md` · `build-warning-policy.md` · `hardening.md` · `release-process.md` · `canonical-json.md` · `trust-safety.md` · `observability-audit.md` · `debug-logging.md` · `log-filtering.md` · `dependencies/index.md` · `matrix-v1.19-client-server-api.md` · `todos/production-milestone.md` · `todos/capability-gaps.md`

## Subdirectory AGENTS.md Files

More specific guidance lives alongside the code it governs. Read the relevant file before working in a module:

| Directory | Focus |
|---|---|
| `src/AGENTS.md` | Implementation conventions: SPDX header, include order, anonymous namespaces, error handling |
| `include/merovingian/AGENTS.md` | Header design: `#pragma once`, forward declarations, namespace rules |
| `src/appservice/AGENTS.md` | Application Service API: registration parsing, namespace matching, masquerading, outbound client |
| `src/auth/AGENTS.md` | Auth: token lifecycle, UIAA, constant-time comparison, password hashing |
| `src/canonicaljson/AGENTS.md` | Canonical JSON: encoding rules, signing pipeline, serializer constraints |
| `src/config/AGENTS.md` | Config: parse-time validation, reload planning, size limit parsing |
| `src/core/AGENTS.md` | Core primitives: `SecretBuffer`, `FileDescriptor`, `Error`, `QueryParams` |
| `src/crypto/AGENTS.md` | Crypto security boundary: libsodium isolation, constant-time, key validation |
| `src/database/AGENTS.md` | Database: prepared statements, backend abstraction, migration rules |
| `src/email/AGENTS.md` | Outbound email: refuse-never-repair address checks, TLS-required SMTP, password read per send, main process only |
| `src/events/AGENTS.md` | Event pipeline: canonical JSON, signing, auth rules, state resolution, redaction |
| `src/federation/AGENTS.md` | Federation security rules: X-Matrix auth, PDU verification, key cache |
| `src/federation_worker/AGENTS.md` | Federation worker process: no signing secret, relay-to-main rules, thread pools, hardening |
| `src/homeserver/AGENTS.md` | Homeserver orchestration: client-server dispatch, local router boundary, media upload |
| `src/http/AGENTS.md` | HTTP transport: rate limiting, header lookup, outbound client |
| `src/identity/AGENTS.md` | Identity Service client: SSRF-safe resolution, HTTPS only, trusted-server allowlist |
| `src/ipc/AGENTS.md` | Worker IPC: authenticated handshake, AEAD framing, reader/dispatch thread split |
| `src/media/AGENTS.md` | Media: internal pipe format, MIME policy, quarantine, thumbnail worker |
| `src/net/AGENTS.md` | Network: TCP acceptor, thread pool, graceful shutdown, CLOEXEC |
| `src/oauth/AGENTS.md` | OAuth 2.0: pure validators, strict URI reader, byte-exact redirect matching, escaped-by-type page renderer |
| `src/observability/AGENTS.md` | Logging: level policy, audit events, secret redaction |
| `src/platform/AGENTS.md` | Platform hardening: seccomp, pledge/Capsicum, ELF probe, self-check, file metadata safety |
| `src/push/AGENTS.md` | Push: pure rule evaluation, gateway SSRF and URL rules, delivery caps |
| `src/rooms/AGENTS.md` | Rooms: room version policy, encryption policy, power levels |
| `src/sync/AGENTS.md` | Sync: stream tokens, sliding sync, long-poll, sync notifier |
| `src/trust_safety/AGENTS.md` | Trust & safety: policy engine, content moderation |
| `tests/unit/AGENTS.md` | Unit test structure and what belongs here vs conformance vs integration |
| `tests/conformance/AGENTS.md` | Conformance test rules: spec citation format, non-negotiable assertions |
| `tests/integration/AGENTS.md` | Integration test structure and real-dependency requirements |
| `tests/fuzz/AGENTS.md` | Fuzz target conventions and regression test policy |
| `tests/smoke/AGENTS.md` | Smoke test scope: startup, basic HTTP, migration |
| `tests/fixtures/AGENTS.md` | Complement fixture format: step schema, supported fields |
| `tests/complement/AGENTS.md` | Complement image: release package only, root entrypoint that drops privileges, config template |
| `tests/support/AGENTS.md` | Test helpers: `MasterKey`, `JsonTestSupport`, `RegistrationToken` |
| `migrations/AGENTS.md` | Migration format, numbering, and safety rules |
| `docs/AGENTS.md` | Which documents to update and when |
| `scripts/AGENTS.md` | Build and lint scripts: what each does, idempotency rules |
| `packaging/AGENTS.md` | OS package metadata: version sync, privilege drop, systemd hardening |
| `security/AGENTS.md` | Security coding rules: update criteria, reject-unsafe gate |

## Matrix Spec v1.19 Reference
Base: docs/matrix-v1.19-spec/index.md

### Core sections
- [Client-Server API](docs/matrix-v1.19-spec/client-server-api.md) — rooms, events, sync, media, filtering
- [Server-Server API](docs/matrix-v1.19-spec/server-server-api.md) — federation, transactions, key exchange, joining rooms
- [Application Service API](docs/matrix-v1.19-spec/application-service-api.md)
- [Identity Service API](docs/matrix-v1.19-spec/identity-service-api.md)
- [Push Gateway API](docs/matrix-v1.19-spec/push-gateway-api.md)

### Frequently referenced subsections
- [Canonical JSON](docs/matrix-v1.19-spec/appendices.md#canonical-json) — canonical JSON encoding rules
- [Signing JSON](docs/matrix-v1.19-spec/appendices.md#signing-json) — how to sign JSON objects
- [Event Signing](docs/matrix-v1.19-spec/appendices.md#event-signing) — event signing test vectors
- [Identifier Grammar](docs/matrix-v1.19-spec/appendices.md#identifier-grammar) — user IDs, room IDs, event IDs
- [Cryptographic Key Representation](docs/matrix-v1.19-spec/appendices.md#cryptographic-key-representation)
- [Security Threat Model](docs/matrix-v1.19-spec/appendices.md#security-threat-model)
- [Room Versions](docs/matrix-v1.19-spec/rooms/index.md) — v1–v12 feature matrix
- [Room v10](docs/matrix-v1.19-spec/rooms/v10.md) · [v11](docs/matrix-v1.19-spec/rooms/v11.md) · [v12 (MSC4291)](docs/matrix-v1.19-spec/rooms/v12.md)
- [Event Authorization Rules](docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules)
- [Signing Events (Federation)](docs/matrix-v1.19-spec/server-server-api.md#signing-events)
- [State Resolution](docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution)
- [Joining Rooms](docs/matrix-v1.19-spec/server-server-api.md#joining-rooms)
- [Server Discovery](docs/matrix-v1.19-spec/client-server-api.md#server-discovery)
- [Client Authentication](docs/matrix-v1.19-spec/client-server-api.md#client-authentication)
- [Room Event Format](docs/matrix-v1.19-spec/client-server-api.md#room-event-format)

## Glossary
| Term | Definition | Code / Spec |
|------|-----------|-------------|
| PDU | Persistent Data Unit — a room event propagated over federation | `federation/`, [spec §pdus](docs/matrix-v1.19-spec/server-server-api.md#pdus) |
| EDU | Ephemeral Data Unit — non-persisted federation message (typing, presence) | `federation/`, [spec §edus](docs/matrix-v1.19-spec/server-server-api.md#edus) |
| Event ID | Unique identifier for a room event (format varies by room version) | `events/EventId.hpp` |
| Auth chain | Sequence of auth events proving an event's validity | `events/Authorization.hpp`, [spec §authorisation-rules](docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules) |
| State resolution | Algorithm to merge divergent room state across forks | `events/StateResolution.hpp`, [spec](docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution) |
| Canonical JSON | Deterministic JSON encoding for signing/hashing | `canonicaljson/`, [spec](docs/matrix-v1.19-spec/appendices.md#canonical-json) |
| Signing key | Ed25519 key pair used to sign events and federation requests | `crypto/Ed25519.hpp` |
| Stream token | Monotonic token for sync pagination | `sync/StreamToken.hpp` |
| Room version | Defines event format, auth rules, and state resolution algorithm | `rooms/RoomVersionPolicy.hpp`, [spec](docs/matrix-v1.19-spec/rooms/index.md) |
| Via servers | List of server names used to route joins (v12/MSC4291) | `federation/` |
| Content hash | SHA-256 hash of event content, used for integrity checks | [spec](docs/matrix-v1.19-spec/server-server-api.md#calculating-the-content-hash-for-an-event) |
| Reference hash | Hash of redacted event, used in event IDs | [spec](docs/matrix-v1.19-spec/server-server-api.md#calculating-the-reference-hash-for-an-event) |
| Redaction | Strips non-essential keys from an event, preserving integrity | `events/Redaction.hpp` |
| Power levels | Per-user permission levels in a room (ban, kick, redact, etc.) | `events/Authorization.hpp` |
| Membership | User's room membership state (join, leave, invite, ban, knock) | `federation/MembershipEndpoints.hpp` |
| Backfill | Retrieving historical events from other servers to fill gaps | [spec](docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events) |
| Transaction | Batch of PDUs/EDUs sent between servers | `federation/Transactions.hpp` |
| Key ID | `algorithm:version` identifier for a signing key | `crypto/`, [spec](docs/matrix-v1.19-spec/appendices.md#cryptographic-key-representation) |
| Complement | The external Matrix homeserver test suite (matrix-org/complement), run against the release package. The JSON flow fixtures under `tests/fixtures/complement/` are this project's own tests, not Complement | `tests/complement/` |

## Build & Test Commands
```bash

# Build and test from Windows, on the Linux VM (docs/dev-environment.md#building-on-a-vm)
python build.py vm

# The same on the FreeBSD VM
python build.py vm --vm freebsd

# Build and test inside WSL instead
python build.py wsl

# Development build via the unified CLI; a target is required
# (linux, bsd, wsl, vm, deb, rpm, pkg, static)
python build.py linux

# Documentation site (see docs/dev-environment.md#documentation-site)
pip install --require-hashes -r requirements-docs.txt
mkdocs build --strict
```

## Pull Requests
Pull request descriptions should have the following headings:
Summary: A short change summary.
What changed: Bullet point list of what changed.
Why it changed: Describe why the change was needed.
CI tests: Bullet point list of all modified tests, and a bullet point list of all new tests.
