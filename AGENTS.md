## Project Overview
The most secure Matrix Protocol homeserver ever created. Secure by design, implementation, and during runtime.

## Language & Stack
- C++26
- LibSodium
- PostgreSQL
- SQLite
- Meson build system

## Code Presentation
- Always wrap code in code blocks with the relevant language tag.
- Include clear, concise inline comments explaining non-obvious logic.
- Show complete, runnable code — avoid partial snippets unless explicitly asked.
- After each code block, briefly explain what changed and why (2–5 sentences max).

## Tone & Style
- Be direct and concise. No filler phrases or lengthy preambles.
- Get to the answer first, then add context if needed.
- Avoid over-explaining things that are straightforward.

## General Rules
- Check the Matrix spec, we MUST conform to v1.18 of the spec.
- The Matrix spec, v1.18, is the authority, not synapse, not your imagination, not any other code.
- Top level namespace should be `merovingian`
- RAII is non negotiable, use it.
- Prefer references over pointers.
- No raw pointers, use smart pointers.
- No calls to new/delete, malloc/free etc. 
- Use std::ignore rather than (void) casting.
- Format C++ code with clang-format using the .clang-format file in the project root.
- If something is ambiguous, ask clarifying questions, never assume.
- Prefer simple, readable solutions over clever ones.
- Flag potential bugs or edge cases after the code explanation if relevant.
- With every change, update the relevant docs. See `docs/CLAUDE.md` for the full list of which documents to update and when.
- Use behaviour driven development in a GIVEN WHEN THEN style.
- Tests should test behaviour and state rather than specific outcomes.
- Create a new test(s) for the desired outcome prior to making the code change.
- Spec conformance tests should be implemented wherever possible.
- After code change, run the new test(s).
- Before creating a new branch from main, pull from origin so that main is up to date.
- Bump the version number on creating a new branch. See versioning doc for all the places where the version number needs updating.
- Record changes for each version in CHANGELOG.md
- Ignore `.clwb` folder.
- Ignore `build*/` directories (Meson build output).
- Always work in feature or bug branches, never main.
- Make the correct change for the ask, not the smallest.
- Update `CHANGELOG.md` on every change.

## Project Layout
Source headers (`include/merovingian/`) and implementations (`src/`) mirror each other by module.

```
├── include/merovingian/   # Public headers (1:1 with src/)
│   ├── auth/              #   Auth service, session tokens, authorization
│   ├── bootstrap/         #   Server bootstrap
│   ├── canonicaljson/     #   Canonical JSON (parser, serializer)
│   ├── config/            #   Runtime config, parser, reload
│   ├── core/              #   Error, file_descriptor, not_null, query_params, secret_buffer
│   ├── crypto/            #   Ed25519, signing, constant-time ops
│   ├── database/          #   Connection, migration, persistent_store, postgresql/sqlite
│   ├── events/            #   Event, event_id, state_resolution, redaction, room_version_policy
│   ├── federation/        #   Inbound/outbound, transactions, key cache, server_discovery, membership
│   ├── homeserver/        #   Server, runtime, listeners, shutdown
│   ├── http/              #   HTTP server, request, rate_limit, connection_guard, tls, session
│   ├── media/             #   Media service, file_metadata
│   ├── net/               #   TCP acceptor, outbound client
│   ├── observability/     #   Logger, observability
│   ├── platform/          #   Runtime hardening, file metadata, self-check
│   ├── rooms/             #   Room service
│   ├── sync/              #   Sync filter, notifier, stream token
│   └── trust_safety/      #   Policy engine, encryption policy
├── src/                   # Implementations (same module dirs as include/)
├── tests/
│   ├── conformance/       #   Catch2 BDD Matrix spec conformance tests
│   ├── unit/              #   Catch2 BDD unit tests (test_*.cpp)
│   ├── integration/       #   Flow/integration tests (test_*_flow.cpp)
│   ├── fuzz/              #   Fuzz targets
│   ├── smoke/             #   Smoke tests
│   ├── fixtures/          #   Test fixtures (complement)
│   └── support/           #   Test helpers (federation_signing_test_support.hpp)
├── migrations/            #   Numbered SQL migrations (001_*.sql …)
├── docs/                  #   All project docs (see list below)
├── scripts/               #   Build, format, lint, dev-setup scripts
├── packaging/             #   OS packages: deb, rpm, freebsd, netbsd, openbsd, systemd, openrc
├── security/              #   Security coding rules
├── config/                #   Runtime config examples
├── subprojects/           #   Meson wrap dependencies
├── meson.build            #   Root build definition
├── meson.options           #   Build options
└── build.py               #   Unified build CLI (Linux, BSD, WSL)
```

### Key entry points
- `src/homeserver/main.cpp` — Application entry point
- `include/merovingian/homeserver/server.hpp` — Top-level server orchestrator
- `include/merovingian/homeserver/runtime.hpp` — Runtime state manager

### Key docs
`architecture.md` · `coding-rules.md` · `testing-standards.md` · `versioning.md` · `threat-model.md` · `security-review-checklist.md` · `crypto-boundary.md` · `database-persistence.md` · `configuration.md` · `auth-identity.md` · `event-engine.md` · `http-transport.md` · `media-repository.md` · `getting-started.md` · `dev-environment.md` · `platform-support.md` · `build-warning-policy.md` · `hardening-alpha-exceptions.md` · `release-process.md` · `canonical-json.md` · `trust-safety.md` · `observability-audit.md` · `matrix-v1.18-client-server-api.md` · `create-room-spec-conformance-plan.md` · `todos/priorities.md` · `todos/beta-milestone.md` · `todos/production-milestone.md` · `todos/capability-gaps.md`

## Subdirectory AGENTS.md Files

More specific guidance lives alongside the code it governs. Read the relevant file before working in a module:

| Directory | Focus |
|---|---|
| `src/AGENTS.md` | Implementation conventions: SPDX header, include order, anonymous namespaces, error handling |
| `include/merovingian/AGENTS.md` | Header design: `#pragma once`, forward declarations, namespace rules |
| `src/crypto/AGENTS.md` | Crypto security boundary: libsodium isolation, constant-time, key validation |
| `src/federation/AGENTS.md` | Federation security rules: X-Matrix auth, PDU verification, key cache |
| `src/events/AGENTS.md` | Event pipeline: canonical JSON, signing, auth rules, state resolution, redaction |
| `tests/unit/AGENTS.md` | Unit test structure and what belongs here vs conformance vs integration |
| `tests/conformance/AGENTS.md` | Conformance test rules: spec citation format, non-negotiable assertions |
| `tests/integration/AGENTS.md` | Integration test structure and real-dependency requirements |
| `tests/fuzz/AGENTS.md` | Fuzz target conventions and regression test policy |
| `migrations/AGENTS.md` | Migration format, numbering, and safety rules |
| `docs/AGENTS.md` | Which documents to update and when |

## Matrix Spec v1.18 Reference
Base: docs/matrix-v1.18-spec/index.md

### Core sections
- [Client-Server API](docs/matrix-v1.18-spec/client-server-api.md) — rooms, events, sync, media, filtering
- [Server-Server API](docs/matrix-v1.18-spec/server-server-api.md) — federation, transactions, key exchange, joining rooms
- [Application Service API](docs/matrix-v1.18-spec/application-service-api.md)
- [Identity Service API](docs/matrix-v1.18-spec/identity-service-api.md)
- [Push Gateway API](docs/matrix-v1.18-spec/push-gateway-api.md)

### Frequently referenced subsections
- [Canonical JSON](docs/matrix-v1.18-spec/appendices.md#canonical-json) — canonical JSON encoding rules
- [Signing JSON](docs/matrix-v1.18-spec/appendices.md#signing-json) — how to sign JSON objects
- [Event Signing](docs/matrix-v1.18-spec/appendices.md#event-signing) — event signing test vectors
- [Identifier Grammar](docs/matrix-v1.18-spec/appendices.md#identifier-grammar) — user IDs, room IDs, event IDs
- [Cryptographic Key Representation](docs/matrix-v1.18-spec/appendices.md#cryptographic-key-representation)
- [Security Threat Model](docs/matrix-v1.18-spec/appendices.md#security-threat-model)
- [Room Versions](docs/matrix-v1.18-spec/rooms/index.md) — v1–v12 feature matrix
- [Room v10](docs/matrix-v1.18-spec/rooms/v10.md) · [v11](docs/matrix-v1.18-spec/rooms/v11.md) · [v12 (MSC4291)](docs/matrix-v1.18-spec/rooms/v12.md)
- [Event Authorization Rules](docs/matrix-v1.18-spec/server-server-api.md#authorization-rules)
- [Signing Events (Federation)](docs/matrix-v1.18-spec/server-server-api.md#signing-events)
- [State Resolution](docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution)
- [Joining Rooms](docs/matrix-v1.18-spec/server-server-api.md#joining-rooms)
- [Server Discovery](docs/matrix-v1.18-spec/client-server-api.md#server-discovery)
- [Client Authentication](docs/matrix-v1.18-spec/client-server-api.md#client-authentication)
- [Room Event Format](docs/matrix-v1.18-spec/client-server-api.md#room-event-format)

## Glossary
| Term | Definition | Code / Spec |
|------|-----------|-------------|
| PDU | Persistent Data Unit — a room event propagated over federation | `federation/`, [spec §pdus](docs/matrix-v1.18-spec/server-server-api.md#pdus) |
| EDU | Ephemeral Data Unit — non-persisted federation message (typing, presence) | `federation/`, [spec §edus](docs/matrix-v1.18-spec/server-server-api.md#edus) |
| Event ID | Unique identifier for a room event (format varies by room version) | `events/event_id.hpp` |
| Auth chain | Sequence of auth events proving an event's validity | `auth/`, [spec §authorization-rules](docs/matrix-v1.18-spec/server-server-api.md#authorization-rules) |
| State resolution | Algorithm to merge divergent room state across forks | `events/state_resolution.hpp`, [spec](docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution) |
| Canonical JSON | Deterministic JSON encoding for signing/hashing | `canonicaljson/`, [spec](docs/matrix-v1.18-spec/appendices.md#canonical-json) |
| Signing key | Ed25519 key pair used to sign events and federation requests | `crypto/ed25519.hpp` |
| Stream token | Monotonic token for sync pagination | `sync/stream_token.hpp` |
| Room version | Defines event format, auth rules, and state resolution algorithm | `events/room_version_policy.hpp`, [spec](docs/matrix-v1.18-spec/rooms/index.md) |
| Via servers | List of server names used to route joins (v12/MSC4291) | `federation/` |
| Content hash | SHA-256 hash of event content, used for integrity checks | [spec](docs/matrix-v1.18-spec/server-server-api.md#calculating-the-content-hash-for-an-event) |
| Reference hash | Hash of redacted event, used in event IDs | [spec](docs/matrix-v1.18-spec/server-server-api.md#calculating-the-reference-hash-for-an-event) |
| Redaction | Strips non-essential keys from an event, preserving integrity | `events/redaction.hpp` |
| Power levels | Per-user permission levels in a room (ban, kick, redact, etc.) | `auth/authorization.hpp` |
| Membership | User's room membership state (join, leave, invite, ban, knock) | `federation/membership_endpoints.hpp` |
| Backfill | Retrieving historical events from other servers to fill gaps | [spec](docs/matrix-v1.18-spec/server-server-api.md#backfilling-and-retrieving-missing-events) |
| Transaction | Batch of PDUs/EDUs sent between servers | `federation/transactions.hpp` |
| Key ID | `algorithm:version` identifier for a signing key | `crypto/`, [spec](docs/matrix-v1.18-spec/appendices.md#cryptographic-key-representation) |
| Complement | Matrix federation test suite (used in integration tests) | `tests/fixtures/complement/` |

## Build & Test Commands
```bash

# Build and test Windows
python build.py wsl

# Format all C++ code
clang-format -i src/**/*.cpp include/merovingian/**/*.hpp

# Full build via unified CLI (Linux/BSD/WSL)
python build.py
```

## Naming Conventions
- **Namespace**: `merovingian::<module>::` (e.g., `merovingian::crypto::`, `merovingian::federation::`)
- **Headers**: `include/merovingian/<module>/<name>.hpp` — one class/struct per file, filename matches primary type
- **Sources**: `src/<module>/<name>.cpp` — mirrors header path exactly
- **Unit tests**: `tests/unit/test_<module>.cpp` — Catch2 BDD style (GIVEN/WHEN/THEN)
- **Integration tests**: `tests/integration/test_<module>_flow.cpp`
- **Migrations**: `migrations/<NNN>_<description>.sql` — zero-padded sequential number
- **Includes**: Use `#include "merovingian/module/name.hpp"` (quotes for project headers; angle brackets for STL and third-party)
- **Test macros**: `TEST_CASE`, `SCENARIO`, `GIVEN`, `WHEN`, `THEN` from Catch2 v3