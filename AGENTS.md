## Project Overview
The most secure Matrix Protocol homeserver ever created. Secure by design, implementation, and during runtime. Bulletproof!

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
- Format C++ code with clang-format using the .clang-format file in the project root.
- If something is ambiguous, ask clarifying questions, never assume.
- Prefer simple, readable solutions over clever ones.
- Flag potential bugs or edge cases after the code explanation if relevant.
- With every change, update the documents in the docs folder.
- Use behaviour driven development in a GIVEN WHEN THEN style.
- Tests should test behaviour and state rather than specific outcomes.
- Create a new test(s) for the desired outcome prior to making the code change.
- Spec conformance tests should be implemented wherever possible.
- After code change, run the new test(s).
- Before creating a new branch from main, pull from origin so that main is up to date.
- Bump the version number on creating a new branch. See versioning doc for all the places where the version number needs updating.
- Record changes for each version in CHANGELOG.md
- Ignore `.clwb` folder.
- Always work in feature or bug branches, never main.
- Make the correct change for the ask, not the smallest.
- Update docs\01-progress-tracker.md on each change, along with the other docs including CHANGELOG.

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
`architecture.md` · `coding-rules.md` · `testing-standards.md` · `versioning.md` · `threat-model.md` · `security-review-checklist.md` · `crypto-boundary.md` · `database-persistence.md` · `configuration.md` · `auth-identity.md` · `event-engine.md` · `http-transport.md` · `media-repository.md` · `getting-started.md` · `dev-environment.md` · `build-warning-policy.md` · `hardening-alpha-exceptions.md` · `release-process.md` · `canonical-json.md` · `trust-safety.md` · `observability-audit.md` · `matrix-v1.18-client-server-api.md` · `create-room-spec-conformance-plan.md` · `01-progress-tracker.md`

## Matrix Spec v1.18 Reference
Base: https://spec.matrix.org/v1.18/

### Core sections
- [Client-Server API](https://spec.matrix.org/v1.18/client-server-api/) — rooms, events, sync, media, filtering
- [Server-Server API](https://spec.matrix.org/v1.18/server-server-api/) — federation, transactions, key exchange, joining rooms
- [Application Service API](https://spec.matrix.org/v1.18/application-service-api/)
- [Identity Service API](https://spec.matrix.org/v1.18/identity-service-api/)
- [Push Gateway API](https://spec.matrix.org/v1.18/push-gateway-api/)

### Frequently referenced subsections
- [Canonical JSON](https://spec.matrix.org/v1.18/appendices/#canonical-json) — canonical JSON encoding rules
- [Signing JSON](https://spec.matrix.org/v1.18/appendices/#signing-json) — how to sign JSON objects
- [Event Signing](https://spec.matrix.org/v1.18/appendices/#event-signing) — event signing test vectors
- [Identifier Grammar](https://spec.matrix.org/v1.18/appendices/#identifier-grammar) — user IDs, room IDs, event IDs
- [Cryptographic Key Representation](https://spec.matrix.org/v1.18/appendices/#cryptographic-key-representation)
- [Security Threat Model](https://spec.matrix.org/v1.18/appendices/#security-threat-model)
- [Room Versions](https://spec.matrix.org/v1.18/rooms/) — v1–v12 feature matrix
- [Room v10](https://spec.matrix.org/v1.18/rooms/v10/) · [v11](https://spec.matrix.org/v1.18/rooms/v11/) · [v12 (MSC4291)](https://spec.matrix.org/v1.18/rooms/v12/)
- [Event Authorization Rules](https://spec.matrix.org/v1.18/server-server-api/#authorization-rules)
- [Signing Events (Federation)](https://spec.matrix.org/v1.18/server-server-api/#signing-events)
- [State Resolution](https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution)
- [Joining Rooms](https://spec.matrix.org/v1.18/server-server-api/#joining-rooms)
- [Server Discovery](https://spec.matrix.org/v1.18/client-server-api/#server-discovery)
- [Client Authentication](https://spec.matrix.org/v1.18/client-server-api/#client-authentication)
- [Room Event Format](https://spec.matrix.org/v1.18/client-server-api/#room-event-format)

## Glossary
| Term | Definition | Code / Spec |
|------|-----------|-------------|
| PDU | Persistent Data Unit — a room event propagated over federation | `federation/`, [spec §pdus](https://spec.matrix.org/v1.18/server-server-api/#pdus) |
| EDU | Ephemeral Data Unit — non-persisted federation message (typing, presence) | `federation/`, [spec §edus](https://spec.matrix.org/v1.18/server-server-api/#edus) |
| Event ID | Unique identifier for a room event (format varies by room version) | `events/event_id.hpp` |
| Auth chain | Sequence of auth events proving an event's validity | `auth/`, [spec §authorization-rules](https://spec.matrix.org/v1.18/server-server-api/#authorization-rules) |
| State resolution | Algorithm to merge divergent room state across forks | `events/state_resolution.hpp`, [spec](https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution) |
| Canonical JSON | Deterministic JSON encoding for signing/hashing | `canonicaljson/`, [spec](https://spec.matrix.org/v1.18/appendices/#canonical-json) |
| Signing key | Ed25519 key pair used to sign events and federation requests | `crypto/ed25519.hpp` |
| Stream token | Monotonic token for sync pagination | `sync/stream_token.hpp` |
| Room version | Defines event format, auth rules, and state resolution algorithm | `events/room_version_policy.hpp`, [spec](https://spec.matrix.org/v1.18/rooms/) |
| Via servers | List of server names used to route joins (v12/MSC4291) | `federation/` |
| Content hash | SHA-256 hash of event content, used for integrity checks | [spec](https://spec.matrix.org/v1.18/server-server-api/#calculating-the-content-hash-for-an-event) |
| Reference hash | Hash of redacted event, used in event IDs | [spec](https://spec.matrix.org/v1.18/server-server-api/#calculating-the-reference-hash-for-an-event) |
| Redaction | Strips non-essential keys from an event, preserving integrity | `events/redaction.hpp` |
| Power levels | Per-user permission levels in a room (ban, kick, redact, etc.) | `auth/authorization.hpp` |
| Membership | User's room membership state (join, leave, invite, ban, knock) | `federation/membership_endpoints.hpp` |
| Backfill | Retrieving historical events from other servers to fill gaps | [spec](https://spec.matrix.org/v1.18/server-server-api/#backfilling-and-retrieving-missing-events) |
| Transaction | Batch of PDUs/EDUs sent between servers | `federation/transactions.hpp` |
| Key ID | `algorithm:version` identifier for a signing key | `crypto/`, [spec](https://spec.matrix.org/v1.18/appendices/#cryptographic-key-representation) |
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
- **Includes**: Use `#include <merovingian/module/name.hpp>` (angle brackets, project-relative)
- **Test macros**: `TEST_CASE`, `SCENARIO`, `GIVEN`, `WHEN`, `THEN` from Catch2 v3