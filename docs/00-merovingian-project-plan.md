# The Merovingian: C++26 Matrix Homeserver Project Plan

## 1. Project summary

**The Merovingian** is a security-first Matrix homeserver written in modern C++26.

The goal is to build a highly secure and hardened Matrix server with encrypted-by-default room policy, hardened federation, strict protocol compliance, conservative dependencies, reproducible builds, strong test discipline, and first-class Linux/BSD support.

Initial protocol target: **Matrix v1.18**. Matrix v1.18 was released on **26 March 2026** and introduced multiple Trust & Safety improvements, including invite blocking, policy servers, account suspension and locking, and reporting API improvements.

Important design constraint: Matrix end-to-end encryption is client-side by design. Homeservers store and route encrypted events and expose device/key APIs for clients, but they should not possess the keys required to read encrypted room message contents. **The Merovingian will preserve that server-blind E2EE model.** “Encryption on by default” means the server defaults new rooms to encrypted, enforces encrypted-room policy where appropriate, implements device and key APIs correctly, avoids logging sensitive metadata, and hardens federation behavior.

---

## 2. Core principles

### Security first

- Secure defaults.
- Hardened runtime profiles.
- Explicit trust boundaries.
- Minimal attack surface.
- No unsafe convenience shortcuts.
- No plaintext secret logging.
- No custom cryptography.
- No large framework dependencies.
- No silent fallback from hardened to weak behavior.
- Preserve Matrix’s server-blind E2EE design.

### Correctness first

Matrix homeserver correctness is security-critical. These areas must be treated as high-risk:

- Event signing.
- Event authorization.
- Canonical JSON.
- State resolution.
- Room version behavior.
- Federation authentication.
- Redaction rules.
- Auth chains.
- Device/key APIs.
- Token handling.
- Media handling.

### Conservative engineering

- Prefer simple, auditable code.
- Prefer small battle-tested libraries.
- Prefer project-owned interfaces around every dependency.
- Prefer explicit resource ownership.
- Prefer portable POSIX-first design.
- Prefer hardened Linux and hardened BSD deployments.

---

## 3. Primary goals

### Functional goals

- Matrix homeserver targeting Matrix v1.18.
- Client-Server API support.
- Server-Server Federation API support.
- Encrypted rooms by default.
- Secure device and key APIs.
- Hardened media repository.
- Hardened federation.
- Admin API.
- Abuse control and Trust & Safety APIs.
- Structured audit logging.
- Metrics and observability.
- Production-ready deployment on Linux and BSD.

### Security goals

- Strong runtime hardening.
- Secure default configuration.
- Minimal dependencies.
- No Boost.
- No raw owning pointers.
- RAII everywhere.
- Compiler warnings maximized.
- Warnings treated as errors.
- Linting required.
- Tests required.
- Static analysis required.
- Sanitizer builds required.
- Fuzzing required for parsers and protocol-critical logic.
- Release hardening evidence recorded.

---

## 4. Non-goals for first release

- Bridges.
- Identity server.
- Voice/video SFU.
- Full-text search.
- Custom encryption protocol.
- Any design that gives the homeserver access to plaintext E2EE message contents.
- Experimental Matrix MSCs by default.
- Windows support as a release blocker.
- Large plugin ecosystem.
- General-purpose web framework.

---

## 5. License

The project is licensed under:

```text
GNU General Public License v3.0 or later
```

Recommended SPDX identifier:

```text
GPL-3.0-or-later
```

For source files:

```cpp
// SPDX-License-Identifier: GPL-3.0-or-later
```

For Meson:

```meson
project(
  'the-merovingian',
  'cpp',
  version: '0.1.0',
  license: 'GPL-3.0-or-later',
)
```

---

## 6. Repository layout

```text
the-merovingian/
  README.md
  SECURITY.md
  COPYING
  meson.build
  meson.options
  subprojects/

  .github/
    workflows/
      ci.yml
      sanitizers.yml
      bsd.yml
      static-analysis.yml
      fuzz-smoke.yml

  docs/
    architecture.md
    threat-model.md
    01-progress-tracker.md
    crypto-boundaries.md
    hardening-guide.md
    federation-security.md
    platform-support.md
    dependency-policy.md
    coding-rules.md
    ci-policy.md

  include/

  src/
    core/
    config/
    net/
      event_loop.hpp
      listener.hpp
      connection.hpp
      tls.hpp
      http1.hpp
      http2.hpp
    http/
    json/
    canonicaljson/
    crypto/
    database/
    auth/
    client_api/
    federation/
    rooms/
    events/
    state/
    sync/
    media/
    policy/
    admin/
    observability/
    workers/
    platform/
      posix/
      linux/
      bsd/
      openbsd/
      freebsd/
    cli/

  tests/
    unit/
    integration/
    federation/
    crypto/
    fuzz/
    property/
    conformance/
    platform/

  tools/
    merovingian-keygen/
    merovingian-config/
    merovingian-db-migrate/
    merovingian-lint-config/
    merovingian-hardening-check/

  packaging/
    systemd/
    openrc/
    rc.d/
    docker/
    deb/
    rpm/
    pkg/
    nix/

  security/
    seccomp/
    apparmor/
    selinux/
    pledge/
    unveil/
    capsicum/
    threat-model/
    audit-checklists/
```

---

## 7. Build system

The Merovingian uses **Meson** as its primary and only supported build system.

### Supported target platforms

- Hardened Linux distributions.
- Hardened BSD environments.
- Standard Linux distributions.
- Standard BSD environments.

The build must succeed on Linux and BSD.

Hardened operating-system environments are preferred first-class targets, not afterthoughts.

### Platform posture

- Portable POSIX-first design.
- No Linux-only dependency in core code unless isolated behind a platform abstraction.
- BSD support tested continuously.
- Linux hardening tested continuously.
- Platform-specific security features isolated behind small capability interfaces.
- Default build produces hardened binaries where supported.
- Unsupported hardening features fail safely or degrade explicitly.
- Hardened profile may fail closed if required hardening is unavailable.

---

## 8. Meson build policy

Meson is responsible for:

- Compiler feature detection.
- Warning policy.
- Warnings-as-errors.
- Sanitizer build options.
- Static-analysis integration.
- Fuzz target registration.
- Test registration.
- Platform feature detection.
- Hardening flag detection.
- Dependency discovery.
- Reproducible build settings where practical.

Required build profiles:

- `debug`
- `debugoptimized`
- `release`
- `asan`
- `ubsan`
- `tsan`
- `fuzz`
- `hardened`

The `hardened` configuration is the preferred production profile.

The project must not rely on developers manually remembering security flags. Hardening must be encoded in Meson options and CI presets.

---

## 9. Meson project skeleton

```meson
project(
  'the-merovingian',
  'cpp',
  version: '0.1.0',
  license: 'GPL-3.0-or-later',
  default_options: [
    'cpp_std=c++26',
    'warning_level=3',
    'werror=true',
    'b_lto=true',
    'b_pie=true',
  ],
)

cpp = meson.get_compiler('cpp')

warning_flags = [
  '-Wall',
  '-Wextra',
  '-Wpedantic',
  '-Wconversion',
  '-Wsign-conversion',
  '-Wshadow',
  '-Wnon-virtual-dtor',
  '-Wold-style-cast',
  '-Wcast-align',
  '-Wunused',
  '-Woverloaded-virtual',
  '-Wnull-dereference',
  '-Wdouble-promotion',
  '-Wformat=2',
  '-Wimplicit-fallthrough',
  '-Werror',
]

hardening_cflags = [
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=3',
  '-fPIE',
  '-fvisibility=hidden',
  '-ftrivial-auto-var-init=zero',
  '-fstack-clash-protection',
  '-fcf-protection=full',
]

hardening_ldflags = [
  '-pie',
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-Wl,-z,noexecstack',
]

add_project_arguments(
  cpp.get_supported_arguments(warning_flags),
  language: 'cpp',
)

add_project_arguments(
  cpp.get_supported_arguments(hardening_cflags),
  language: 'cpp',
)

add_project_link_arguments(
  cpp.get_supported_link_arguments(hardening_ldflags),
  language: 'cpp',
)

subdir('src')
subdir('tests')
```

---

## 10. Compiler and linker hardening

### Baseline GCC/Clang warning policy

```text
-Wall
-Wextra
-Wpedantic
-Wconversion
-Wsign-conversion
-Wshadow
-Wnon-virtual-dtor
-Wold-style-cast
-Wcast-align
-Wunused
-Woverloaded-virtual
-Wnull-dereference
-Wdouble-promotion
-Wformat=2
-Wimplicit-fallthrough
-Werror
```

### Optional MSVC policy if Windows support is added later

```text
/W4
/WX
/permissive-
```

Linux and BSD builds are the priority. MSVC is not a release blocker unless Windows support becomes an explicit target.

### Preferred compiler hardening flags

```text
-fstack-protector-strong
-D_FORTIFY_SOURCE=3
-fPIE
-fno-plt where supported
-fvisibility=hidden
-fstrict-flex-arrays=3 where supported
-ftrivial-auto-var-init=zero where supported
-fcf-protection=full where supported
-fstack-clash-protection where supported
```

### Preferred linker hardening flags

```text
-pie
-Wl,-z,relro
-Wl,-z,now
-Wl,-z,noexecstack
-Wl,--as-needed where supported
```

### Rules

- Hardening flags must be feature-tested.
- Unsupported flags must not break portability.
- Hardened profile must fail if required guarantees are unavailable and no explicit override is provided.
- Release artifacts must record which hardening features were enabled.

---

## 11. C++26 policy

The project uses C++26, but production code should not depend blindly on immature compiler support.

### Allowed immediately

- `std::span`
- `std::string_view`
- `std::expected`-style error handling where available.
- `std::chrono`
- Strong value types.
- RAII wrappers.
- Ranges where clarity is improved.
- Modern atomics where needed.

### Experimental or gated

- Contracts.
- Reflection.
- Modules.
- Advanced compile-time metaprogramming that harms portability.
- Compiler-specific C++26 features.

### Policy

```text
Language mode: C++26
Production profile: portable subset only
Experimental profile: contracts/reflection/modules behind build options
No feature may compromise Linux/BSD portability
```

---

## 12. Coding rules

- Prefer references over pointers.
- Use pointers only when nullability or reseating is semantically required.
- Prefer smart pointers or explicit non-owning wrapper types where pointer semantics are required.
- No raw owning pointers.
- Avoid raw pointers in application code unless explicitly justified in a reviewed exception.
- Use RAII for every resource.
- Create small, explicit wrapper types for resources that need ownership, cleanup, locking, lifetime control, or invariant enforcement.
- No manual `new` or `delete`.
- No manual `malloc` or `free` outside approved low-level wrappers.
- No unchecked resource handles.
- File descriptors, sockets, database handles, memory maps, locks, temporary files, cryptographic contexts, and OS handles must be wrapped.
- Compiler warnings must be enabled at the highest practical level.
- All warnings are errors.
- Code must pass formatting, linting, unit tests, integration tests, static analysis, and sanitizer builds before merge.
- No merge is allowed with failing tests, skipped security checks, unresolved static-analysis findings, or new compiler warnings.

### Additional C++ rules

- Ban raw owning pointers.
- Ban implicit ownership transfer.
- Ban unchecked narrowing conversions.
- Ban exceptions across module boundaries.
- Ban unbounded recursion over remote-controlled input.
- Ban unsafe string formatting.
- Ban global mutable state unless explicitly reviewed.
- Ban long-lived locks across I/O.
- Ban logging secrets.
- Ban parsing untrusted data without bounds.
- Prefer immutable parsed event objects.
- Prefer explicit error types over ambiguous booleans.
- Prefer strong typedefs for IDs, tokens, keys, room IDs, event IDs, server names, and user IDs.

---

## 13. Dependency policy

- Boost is not allowed.
- Prefer small, simple, battle-proven libraries.
- Prefer libraries with a strong security record, stable APIs, active maintenance, and conservative design.
- Prefer C libraries with narrow interfaces when they are easier to audit and wrap safely.
- Every dependency must have a clear owner, purpose, license review, security review, and update policy.
- Every dependency must be wrapped behind a project-owned interface before use in application code.
- Dependencies must not leak throughout the codebase.
- Avoid large framework-style dependencies.
- Avoid dependencies with global mutable state where practical.
- Avoid dependencies that require exceptions, RTTI, custom allocators, or invasive build assumptions.
- Avoid dependencies that are Linux-only unless isolated behind a platform abstraction.
- Avoid dependencies that are hard to build on BSD.
- Avoid dependencies with weak release hygiene, unclear maintainership, or frequent breaking changes.
- Vendoring is allowed only for small, security-reviewed dependencies or when required for reproducible builds.
- Network-facing parsers, cryptographic libraries, compression libraries, image/media libraries, and database clients require extra review.
- Dependencies must be fuzzed at project integration boundaries where practical.

### Dependency approval rule

A dependency is not accepted because it is convenient.

Before adding a dependency, document:

- Why it is needed.
- Why project-owned code is worse.
- Why smaller alternatives are insufficient.
- Security history.
- Maintenance status.
- License.
- Supported platforms.
- BSD build status.
- Fuzzing or test coverage.
- Whether it handles untrusted input.
- How it will be wrapped.
- How it will be updated or removed.

---

## 14. Initial dependency shortlist

Subject to security review.

### Cryptography

- `libsodium` for modern cryptographic primitives.
- OpenSSL, LibreSSL, or BoringSSL for TLS, selected per platform support and auditability.
- TLS provider must be hidden behind a project-owned abstraction.
- Server signing key handling must be isolated.

### JSON

Selected dependency:

- `yyjson` for strict RFC 8259 parsing behind the project-owned canonical JSON
  boundary.

Previously considered:

- `simdjson`
- `jansson`

Rules:

- Canonical JSON serialization remains project-owned.
- Parsed JSON is copied into `merovingian::canonicaljson::Value`; no `yyjson_*`
  type crosses the module boundary.
- Duplicate-key rejection must be verified.
- UTF-8 validation must be verified.
- Integer bounds must be verified.
- Signing semantics must be tested by The Merovingian, not assumed from the library.

### HTTP

- `llhttp` for HTTP/1.1 parsing.
- `nghttp2` for HTTP/2 when required.

### Database

- `libpq` for PostgreSQL.
- Database access wrapped behind project-owned RAII types.
- Prepared statements only.

### Compression

- `zlib-ng` or `zlib`, only where protocol-required.
- Compression must be bounded to prevent decompression bombs.

### Event loop

- Prefer a project-owned event loop abstraction.
- Backend may use:
  - `kqueue`
  - `epoll`
  - portable POSIX polling
- External event-loop libraries require explicit approval.

### Logging

- Prefer project-owned structured logging.
- If a dependency is used, it must support:
  - structured fields
  - redaction
  - no accidental secret formatting
  - bounded allocation behavior

### Testing

- `Catch2` or `doctest`
- `libFuzzer`
- AFL++
- Sanitizers
- Project-owned property testing initially if needed.

### Static analysis and linting

- `clang-tidy`
- `clang-format`
- `cppcheck`
- CodeQL where available.
- include-what-you-use where practical.

---

## 15. Rejected dependencies and approaches

### Rejected

- Boost.
- Boost.Beast.
- Boost.Asio.
- Large web frameworks.
- Header-only framework stacks.
- Custom cryptography.
- Convenience dependencies that are hard to audit.
- Linux-only core dependencies.
- Dependencies that cannot be built reliably on BSD.
- Dependencies that leak types across the whole codebase.
- Any server-side design that gives the homeserver plaintext access to encrypted room messages.

### Networking architecture update

The Merovingian does not use Boost.

Networking is built around a project-owned runtime abstraction with small platform backends:

```text
src/net/
  event_loop.hpp
  listener.hpp
  connection.hpp
  tls.hpp
  http1.hpp
  http2.hpp

src/platform/
  posix/
  linux/
  bsd/
  openbsd/
  freebsd/
```

The HTTP layer is not a general web framework. It is a narrowly scoped Matrix API transport layer with strict limits, explicit lifetimes, and fuzzed parsers.

---

## 16. Runtime architecture

```text
main process
  ├── client API listener
  ├── federation API listener
  ├── sync/notifier workers
  ├── federation workers
  ├── database executor pool
  ├── background job scheduler
  ├── media worker sandbox
  ├── signing service
  └── admin control interface
```

### Preferred service split

```text
merovingian-server       main API/federation process
merovingian-media        sandboxed media processor
merovingian-signer       private signing key service
merovingian-admin        local-only admin control socket
merovingian-migrator     offline DB migration tool
```

### Design rules

- Structured concurrency.
- Explicit cancellation.
- Bounded queues.
- Bounded memory.
- Backpressure everywhere.
- No hidden thread pools.
- No unbounded task spawning.
- No blocking DNS or network I/O on critical event loops.
- No secrets in core dumps where avoidable.
- Separate privilege domains where practical.

---

## 17. Linux and BSD platform support

### Target BSDs

- OpenBSD.
- FreeBSD.
- HardenedBSD where available.
- NetBSD as a portability target where feasible.

### Target Linux environments

- Debian stable.
- Ubuntu LTS.
- Fedora.
- Arch.
- Alpine/musl.
- Hardened Gentoo or equivalent hardened profile where feasible.

### Platform abstractions

```text
src/platform/
  posix/
  linux/
  bsd/
  openbsd/
  freebsd/
```

Platform abstractions should cover:

- Sockets.
- File descriptors.
- Process sandboxing.
- Privilege dropping.
- Filesystem permissions.
- Random source access.
- Memory locking.
- Secure temporary files.
- Signal handling.
- Daemon supervision.
- Resource limits.
- Kernel security facilities.

---

## 18. Runtime hardening targets

### Linux hardening support

- systemd sandboxing.
- seccomp-bpf.
- Landlock where useful.
- AppArmor profile.
- SELinux policy notes.
- Linux namespaces where appropriate.
- Capability bounding set.
- `no_new_privs`.
- Read-only filesystem support.
- Private temporary directories.
- Restricted address families.
- Resource limits.

### BSD hardening support

- OpenBSD `pledge`.
- OpenBSD `unveil`.
- FreeBSD Capsicum where practical.
- FreeBSD jails deployment guide.
- HardenedBSD deployment notes.
- `chroot` support where appropriate.
- `setrlimit`.
- Privilege dropping.
- Strict filesystem permissions.

### Startup hardening self-check

The server should expose a startup self-check that reports:

```text
compiler hardening
linker hardening
PIE status
RELRO status
stack protector status
FORTIFY status
seccomp status
pledge/unveil status
capsicum status
privilege drop status
filesystem restrictions
core dump policy
secret redaction policy
```

Runtime hardening is a product feature.

---

## 19. HTTP and networking

### Policy

- Boost.Beast is not allowed.
- Boost.Asio is not allowed.
- Avoid framework-style HTTP servers.
- Avoid hidden thread pools.
- Avoid callback-heavy APIs that obscure lifetime and cancellation.
- Enforce request limits before allocation-heavy parsing.
- Treat HTTP/2 as a separate optional implementation layer until HTTP/1.1 is secure and complete.

### HTTP/1.1

Candidate:

- `llhttp`

Requirements:

- Strict request size limits.
- Header size limits.
- Header count limits.
- Method/path validation.
- Slowloris protection.
- Request body streaming.
- Bounded memory.
- Fuzzed parser integration.
- Per-endpoint rate limits.
- Structured errors.

### HTTP/2

Candidate:

- `nghttp2`

Rules:

- Optional at first.
- Separate implementation path.
- Strict stream limits.
- Strict frame limits.
- HPACK limits.
- Flow-control sanity checks.
- Independent fuzzing.

### Socket backends

- `kqueue` on BSD.
- `epoll` on Linux.
- Portable POSIX fallback where needed.
- Linux-only fast paths must be optional and isolated.

---

## 20. JSON and canonical JSON

Matrix signing depends heavily on canonical JSON. This module is security-critical.

```text
src/canonicaljson/
  parse_lossless()
  serialize_canonical()
  reject_duplicate_keys()
  enforce_integer_ranges()
  normalize_utf8()
  signable_object_view()
```

### Rules

- Reject duplicate object keys.
- Reject invalid UTF-8.
- Enforce integer limits.
- Preserve signing semantics.
- Avoid lossy parse/serialize cycles.
- Fuzz all inputs.
- Differential-test against known Matrix fixtures.
- Project-owned canonical serializer.
- JSON dependency must not determine Matrix signing semantics.

---

## 21. Event engine

The event engine is the core of the homeserver.

```text
src/events/
  event_id.hpp
  event_builder.hpp
  event_parser.hpp
  event_signer.hpp
  event_authenticator.hpp
  redaction_engine.hpp
  event_persistence.hpp

src/rooms/
  room_version_registry.hpp
  room_version_policy.hpp
  power_levels.hpp
  membership.hpp

src/state/
  state_resolver.hpp
  auth_chain.hpp
  state_group.hpp
```

### Responsibilities

- Event creation.
- Event parsing.
- Event signing.
- Event signature verification.
- Event authorization.
- Auth event selection.
- State resolution.
- Redactions.
- Power levels.
- Event DAG persistence.
- Room version behavior.
- Room membership behavior.

### Room version policy shape

```cpp
struct RoomVersionPolicy {
    std::string_view id;
    EventFormat event_format;
    RedactionRules redaction_rules;
    AuthRules auth_rules;
    StateResolutionAlgorithm state_resolution;
    EventIdFormat event_id_format;
};
```

### Required tests

- Room version fixtures.
- Auth rule tests.
- Redaction tests.
- State resolution tests.
- Event ID tests.
- Signature tests.
- Federation acceptance/rejection tests.

---

## 22. Federation

Federation is the most hostile surface.

```text
src/federation/
  discovery/
  signing/
  transactions/
  send_join/
  send_leave/
  invite/
  backfill/
  edu/
  remote_server_registry/
  federation_acl/
  remote_rate_limiter/
  quarantine/
```

### Federation security posture

- Strict TLS verification.
- Certificate pinning option.
- DNS resolution hardening.
- DNS rebinding protection.
- SSRF protection.
- Private IP blocking by default for outbound federation/media fetches.
- Timeout ceilings.
- Backoff and circuit breakers.
- Per-remote-server reputation.
- Request signing verification.
- Event signature verification.
- Remote media isolation.
- Federation quarantine mode.
- Explicit federation allow/deny policies.
- No blind trust in remote server-provided JSON.

### Federation defaults

```yaml
security:
  federation:
    enabled: true
    default_policy: allow
    deny_ip_ranges:
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - ::1/128
      - fc00::/7
    require_valid_tls: true
    verify_json_signatures: true
    max_transaction_size: 10MiB
    remote_timeout: 30s
```

---

## 23. Encryption-default policy

Matrix E2EE is designed to keep encrypted room message contents unreadable to homeservers. The Merovingian must preserve that property.

### Server behavior

- New private rooms default to encrypted.
- Direct messages default to encrypted.
- Admin policy can require encryption for private rooms.
- Admin policy can disallow unencrypted DMs.
- Admin policy can disallow unencrypted federated private rooms.
- Public rooms may allow unencrypted mode only by policy.
- The server stores and routes encrypted events.
- The server implements the device, key, and backup APIs required by Matrix clients.
- The server does not possess plaintext room message contents for encrypted rooms.
- The server does not introduce a mechanism to gain plaintext access to encrypted room messages.
- Encrypted event payloads are never logged.
- Moderation relies on metadata, reports, policy tools, and client-side reporting rather than server-side message inspection.

### Suggested config

```yaml
security:
  encryption:
    default_for_new_rooms: true
    require_for_direct_messages: true
    require_for_private_rooms: true
    allow_unencrypted_public_rooms: true
    block_unencrypted_federated_private_rooms: true
    redact_encrypted_event_content_from_logs: true
```

### Key API support

- One-time key upload.
- One-time key query.
- One-time key claim.
- Fallback keys.
- Device list updates.
- Cross-signing key storage.
- Key backup APIs.
- Device verification metadata.
- Strict rate limits for key endpoints.

---

## 24. Cryptography

### Rules

- No custom crypto.
- No homegrown random number generation.
- No non-reviewed cryptographic primitives.
- Constant-time comparison wrappers.
- Zeroization for secrets.
- Key rotation support.
- Separate server signing key from TLS key.
- Multiple active signing keys for rotation.
- Audit event for every key lifecycle change.
- Offline signing-key backup support.
- Optional hardware-backed key support later.
- No design that grants the homeserver access to plaintext E2EE room messages.

### Candidate libraries

- `libsodium` for modern cryptographic primitives.
- OpenSSL, LibreSSL, or BoringSSL for TLS.

### Crypto service boundary

```text
src/crypto/
  random.hpp
  secure_buffer.hpp
  constant_time.hpp
  ed25519.hpp
  signing_service.hpp
  tls_provider.hpp
  key_rotation.hpp
```

---

## 25. Database design

Recommended initial database: PostgreSQL via `libpq`.

### Rules

- Runtime DB access through project-owned RAII wrappers.
- Prepared statements only.
- Tokens stored hashed.
- Clear transaction boundaries.
- Separate migration role and runtime role.
- Append-only audit log.
- DB migrations tested.
- No SQL string concatenation with untrusted input.
- No ORM dependency unless separately justified.
- Encrypted event payloads are stored as encrypted event payloads, not plaintext.

### Core tables

```text
users
devices
access_tokens
refresh_tokens
server_signing_keys
rooms
room_versions
events
event_json
event_edges
event_auth
event_signatures
current_state
state_groups
state_group_edges
membership
invites
account_data
push_rules
filters
one_time_keys
fallback_keys
cross_signing_keys
key_backups
media
remote_media
federation_destinations
federation_transactions
rate_limits
audit_log
policy_rules
admin_actions
```

---

## 26. Media repository

Media is high-risk.

### Requirements

- Size limits.
- MIME validation.
- Content sniffing policy.
- Optional AV scanner hook.
- Quarantine support.
- Remote media isolation.
- No automatic unsafe image decoding in main process.
- Sandboxed media worker.
- SSRF protection.
- Private IP blocking for remote fetches.
- Decompression bomb protection.
- Hash-based deduplication.
- Admin quarantine tools.

### Suggested config

```yaml
security:
  media:
    max_upload_size: 50MiB
    quarantine_unknown_mime: true
    enable_av_scanner: true
    block_private_ip_fetches: true
    remote_fetch_timeout: 30s
    decode_in_sandbox: true
```

---

## 27. Authentication and authorization

### Required features

- User registration disabled by default.
- Registration tokens.
- Login.
- Logout.
- Refresh tokens.
- Device management.
- Access token hashing.
- Admin bootstrap.
- Password policy.
- Rate limiting.
- Session invalidation.
- Account locking.
- Account suspension.
- Audit events for auth-sensitive actions.

### Token rules

- Never store plaintext access tokens.
- Never log tokens.
- Use constant-time comparison for token hashes where applicable.
- Support token revocation.
- Support device-specific logout.
- Support global logout.
- Refresh token rotation.

---

## 28. Trust & Safety

### Implement early

- Invite blocking.
- Policy server support.
- Account suspension.
- Account locking.
- Reporting APIs.
- Admin room quarantine.
- Federation quarantine.
- Media quarantine.
- Rate-limit policies.
- Abuse audit logs.
- Admin-visible enforcement reasons.

### Policy engine

```text
src/policy/
  policy_engine.hpp
  invite_policy.hpp
  federation_policy.hpp
  media_policy.hpp
  registration_policy.hpp
  room_policy.hpp
  account_policy.hpp
```

---

## 29. Configuration model

Secure default configuration:

```yaml
server:
  name: example.org
  public_baseurl: https://matrix.example.org
  trusted_proxies: []

listeners:
  client:
    bind: 127.0.0.1:8008
    tls: false
  federation:
    bind: 127.0.0.1:8448
    tls: false

database:
  uri_file: /etc/merovingian/db-uri
  pool_size: 16

security:
  registration:
    enabled: false
    require_token: true

  encryption:
    default_for_new_rooms: true
    require_for_direct_messages: true
    require_for_private_rooms: true
    allow_unencrypted_public_rooms: true
    block_unencrypted_federated_private_rooms: true

  federation:
    enabled: true
    default_policy: allow
    require_valid_tls: true
    verify_json_signatures: true
    deny_ip_ranges:
      - 127.0.0.0/8
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - ::1/128
      - fc00::/7

  media:
    max_upload_size: 50MiB
    quarantine_unknown_mime: true
    enable_av_scanner: true
    block_private_ip_fetches: true
    decode_in_sandbox: true

  logging:
    redact_tokens: true
    redact_event_content: true
    structured: true
```

---

## 30. Testing strategy

### Required test layers

```text
unit tests
integration tests
federation tests
client API tests
database migration tests
property tests
state-resolution tests
canonical JSON tests
signature tests
fuzz tests
load tests
chaos tests
upgrade/downgrade tests
platform hardening tests
```

### Fuzz targets

High priority:

- JSON parser integration.
- Canonical JSON serializer.
- HTTP/1 parser integration.
- HTTP/2 frame handling.
- Matrix event parser.
- Event authorization.
- State resolution.
- Federation transaction parser.
- Media metadata parser.
- Config parser.
- URI parser.
- Signature verification inputs.
- Compression handling.

### Sanitizer builds

```text
ASAN
UBSAN
TSAN
MSAN where practical
LSAN
```

### Differential testing

Compare behavior against established Matrix homeservers where possible:

- Synapse.
- Dendrite.
- Conduit/Conduwuit where relevant.
- Matrix spec fixtures.

---

## 31. Static analysis and linting

Every merge must pass:

```text
clang-format
clang-tidy
cppcheck
include-what-you-use where practical
CodeQL where available
secret scanning
dependency audit
license scanning
```

No merge with:

- New compiler warnings.
- Failing tests.
- Disabled tests without justification.
- Unresolved static-analysis findings.
- Unreviewed dependency changes.
- Missing protocol coverage updates.

---

## 32. CI policy

Primary CI should use **GitHub Actions**.

GitHub Actions usage is free for public repositories using standard GitHub-hosted runners, which makes it suitable for a public GPLv3 project.

GitHub’s native hosted runners are not BSD runners. For BSD testing, use BSD VM actions running inside GitHub Actions. The `vmactions` project provides FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and related VM actions.

### Required Linux CI

```text
GCC release
Clang release
GCC hardened
Clang hardened
ASAN/UBSAN
TSAN
Alpine/musl
```

### Required BSD CI

```text
FreeBSD release
OpenBSD release
NetBSD optional
HardenedBSD optional when reliable CI is available
OpenBSD pledge/unveil-enabled runtime test
FreeBSD Capsicum-enabled runtime test where practical
```

### Every merge must prove

- Linux build succeeds.
- BSD build succeeds.
- Hardened Linux build succeeds.
- Hardened BSD build succeeds where supported.
- Unit tests pass.
- Integration tests pass.
- Static analysis passes.
- Linting passes.
- No compiler warnings are introduced.

---

## 33. Suggested GitHub Actions CI

Initial `.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
  pull_request:

jobs:
  linux-gcc:
    name: Linux GCC
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y g++ meson ninja-build pkg-config libssl-dev libsodium-dev libpq-dev

      - name: Configure
        run: meson setup build -Dbuildtype=debugoptimized

      - name: Build
        run: meson compile -C build

      - name: Test
        run: meson test -C build --print-errorlogs

  linux-clang:
    name: Linux Clang
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang meson ninja-build pkg-config libssl-dev libsodium-dev libpq-dev

      - name: Configure
        run: CXX=clang++ meson setup build -Dbuildtype=debugoptimized

      - name: Build
        run: meson compile -C build

      - name: Test
        run: meson test -C build --print-errorlogs

  linux-ubsan:
    name: Linux UBSan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang meson ninja-build pkg-config libssl-dev libsodium-dev libpq-dev

      - name: Configure
        run: CXX=clang++ meson setup build -Db_sanitize=undefined -Dbuildtype=debugoptimized

      - name: Build
        run: meson compile -C build

      - name: Test
        run: meson test -C build --print-errorlogs

  linux-tsan:
    name: Linux TSan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang meson ninja-build pkg-config libssl-dev libsodium-dev libpq-dev

      - name: Configure
        run: CXX=clang++ meson setup build -Db_sanitize=thread -Dbuildtype=debugoptimized

      - name: Build
        run: meson compile -C build

      - name: Test
        run: meson test -C build --print-errorlogs

  linux-hardened:
    name: Linux Hardened
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y clang meson ninja-build pkg-config libssl-dev libsodium-dev libpq-dev

      - name: Configure
        run: CXX=clang++ meson setup build -Dbuildtype=release -Dhardened=true

      - name: Build
        run: meson compile -C build

      - name: Test
        run: meson test -C build --print-errorlogs

  freebsd:
    name: FreeBSD
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: vmactions/freebsd-vm@v1
        with:
          usesh: true
          prepare: |
            pkg install -y meson ninja pkgconf llvm openssl libsodium postgresql17-client
          run: |
            c++ --version
            meson setup build -Dbuildtype=debugoptimized
            meson compile -C build
            meson test -C build --print-errorlogs

  openbsd:
    name: OpenBSD
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: vmactions/openbsd-vm@v1
        with:
          prepare: |
            pkg_add meson ninja pkgconf openssl libsodium postgresql-client
          run: |
            c++ --version
            meson setup build -Dbuildtype=debugoptimized
            meson compile -C build
            meson test -C build --print-errorlogs
```

### Future CI expansion

Add separate workflows for:

```text
static-analysis.yml
sanitizers.yml
fuzz-smoke.yml
bsd.yml
hardened.yml
dependency-audit.yml
release.yml
```

Add optional BSD jobs:

```yaml
netbsd:
  name: NetBSD
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - uses: vmactions/netbsd-vm@v1
      with:
        prepare: |
          pkgin -y install meson ninja-build pkg-config clang openssl libsodium postgresql17-client
        run: |
          c++ --version
          meson setup build -Dbuildtype=debugoptimized
          meson compile -C build
          meson test -C build --print-errorlogs
```

---

## 34. Protocol coverage tracking

Maintain:

```text
docs/01-progress-tracker.md
```

For every endpoint:

```text
Endpoint
Spec version
Implemented
Tested
Fuzzed
Federation-sensitive
Auth required
Rate-limited
Security notes
Compatibility notes
```

### Version policy

- Initial target: Matrix v1.18.
- Unstable MSCs disabled by default.
- Security-relevant MSCs may be implemented behind feature flags.
- Every spec upgrade requires:
  - coverage diff
  - migration review
  - compatibility testing
  - security review

---

## 35. Observability and audit logging

### Structured logs

- JSON logs.
- Redacted secrets.
- Redacted event content.
- Request IDs.
- User IDs where safe.
- Device IDs where safe.
- Remote server names.
- Admin action IDs.
- Policy decision IDs.

### Audit log

Append-only audit log for:

- Admin actions.
- Login failures.
- Account locking.
- Account suspension.
- Key rotation.
- Federation quarantine.
- Media quarantine.
- Registration changes.
- Policy changes.
- Permission changes.

### Metrics

- Request latency.
- Endpoint errors.
- Federation failures.
- Remote server backoff.
- DB pool saturation.
- Sync latency.
- Event authorization latency.
- Media quarantine count.
- Rate-limit triggers.
- Hardening self-check status.

---

## 36. Supply-chain security

### Required

- Pinned dependencies.
- Lockfiles where practical.
- SBOM generation.
- Signed release artifacts.
- Reproducible release builds where practical.
- Dependency vulnerability scanning.
- License review.
- Release provenance.
- Container image signing if containers are published.

### Release artifacts must include

```text
version
git commit
compiler
compiler flags
linker flags
enabled hardening features
dependency versions
SBOM
test summary
fuzzing summary
known limitations
```

---

## 37. Milestone plan

Historical note: this numbered milestone plan is retained as an original project
planning sketch. Current progress, readiness, and Matrix v1.18 coverage are
tracked in `docs/01-progress-tracker.md`.

### Milestone 0: skeleton and hardening foundation

Deliverables:

- Meson project.
- GPLv3 license files.
- Linux/BSD GitHub Actions CI.
- Warning policy.
- Warnings-as-errors.
- Sanitizer builds.
- clang-format.
- clang-tidy.
- cppcheck.
- Basic logging.
- Config parser.
- Platform abstraction skeleton.
- HTTP parser integration spike.
- Threat model v0.
- Dependency policy.
- Coding rules.
- Hardening guide v0.

### Milestone 1: core runtime

Deliverables:

- Event loop abstraction.
- POSIX backend.
- Linux backend.
- BSD backend.
- RAII wrappers for:
  - file descriptors
  - sockets
  - timers
  - signals
  - memory maps
  - process handles
- Structured error model.
- Bounded task queues.
- Runtime cancellation.
- Startup hardening self-check.

### Milestone 2: auth and identity

Deliverables:

- Server name config.
- User model.
- Registration disabled by default.
- Admin bootstrap.
- Login.
- Logout.
- Refresh tokens.
- Device IDs.
- Access token hashing.
- Rate limiting.
- Audit log for auth events.

### Milestone 3: JSON, signing, and events

Deliverables:

- JSON parser wrapper.
- Canonical JSON serializer.
- Duplicate-key rejection.
- UTF-8 validation.
- Event model.
- Event signing.
- Signature verification.
- Room version registry.
- Event persistence.
- Unit/fuzz tests.

### Milestone 4: rooms and sync

Deliverables:

- Room creation.
- Membership.
- Power levels.
- Current state.
- Timeline.
- Basic `/sync`.
- Filters.
- Lazy loading.
- Redactions.
- State resolution tests.

### Milestone 5: encryption policy and key APIs

Deliverables:

- Encrypted rooms by default.
- One-time keys.
- Fallback keys.
- Device list updates.
- Cross-signing key storage.
- Key backup APIs.
- Encryption enforcement policy.
- Redacted logging tests.
- Tests proving encrypted room event contents are stored and routed as encrypted payloads only.

### Milestone 6: federation MVP

Deliverables:

- Server discovery.
- TLS verification.
- Signed federation requests.
- Transaction send/receive.
- Invite.
- Join.
- Leave.
- Backfill.
- Federation rate limits.
- Remote server quarantine.
- SSRF protections.

### Milestone 7: media and sandboxing

Deliverables:

- Local media upload/download.
- Remote media fetch.
- Media quarantine.
- Sandboxed media worker.
- AV scanner hook.
- MIME policy.
- Size limits.
- Decompression protections.
- SSRF protections.

### Milestone 8: Trust & Safety

Deliverables:

- Invite blocking.
- Policy server support.
- Account locking.
- Account suspension.
- Reporting APIs.
- Federation policy engine.
- Admin moderation API.
- Audit log integration.

### Milestone 9: hardened alpha

Deliverables:

- systemd hardening.
- seccomp profile.
- AppArmor profile.
- OpenBSD pledge/unveil profile.
- FreeBSD Capsicum support where practical.
- FreeBSD jail guide.
- HardenedBSD notes.
- Reproducible build notes.
- SBOM.
- Signed artifacts.
- Protocol coverage report.

---

## 38. Immediate files to create

```text
README.md
SECURITY.md
COPYING
meson.build
meson.options
src/meson.build
tests/meson.build

.github/workflows/ci.yml

docs/threat-model.md
docs/architecture.md
docs/01-progress-tracker.md
docs/crypto-boundaries.md
docs/hardening-guide.md
docs/platform-support.md
docs/dependency-policy.md
docs/coding-rules.md
docs/ci-policy.md

security/seccomp/
security/apparmor/
security/selinux/
security/pledge/
security/unveil/
security/capsicum/

src/core/
src/http/
src/net/
src/config/
src/canonicaljson/
src/crypto/
src/platform/
src/platform/posix/
src/platform/linux/
src/platform/bsd/
src/platform/openbsd/
src/platform/freebsd/

tests/unit/
tests/fuzz/
tests/platform/
```

---

## 39. Definition of “most secure”

This must be measurable.

```text
Protocol compliance
  - Matrix v1.18 coverage
  - room version coverage
  - federation compatibility

Cryptographic hygiene
  - no custom crypto
  - key rotation
  - signing-key audit logs
  - encrypted room policy
  - key API correctness
  - no homeserver access to plaintext encrypted-room message contents

Memory-safety discipline
  - no raw owning pointers
  - RAII everywhere
  - sanitizer-clean
  - fuzz coverage
  - static analysis clean
  - unsafe-code exception review

Operational hardening
  - hardened Linux support
  - hardened BSD support
  - systemd sandbox
  - seccomp/AppArmor
  - pledge/unveil
  - Capsicum where practical
  - read-only filesystem support
  - minimal privileges

Abuse resistance
  - invite blocking
  - account locking/suspension
  - policy server support
  - media quarantine
  - federation quarantine

Supply chain
  - pinned dependencies
  - SBOM
  - signed releases
  - reproducible builds where practical
  - vulnerability scanning

Engineering discipline
  - Meson-only build
  - Linux/BSD CI
  - max warnings
  - warnings as errors
  - linted
  - tested
  - statically analyzed
```

---

## 40. Project tagline

```text
The Merovingian is a security-first Matrix homeserver written in modern C++,
designed for encrypted-by-default communication, hardened federation, strict
protocol correctness, and auditable operation on hardened Linux and BSD systems.
```
