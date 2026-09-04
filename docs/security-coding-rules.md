# Security coding rules

This is the single authoritative, explained reference for every security-relevant coding
rule enforced across Merovingian. It supersedes `security/coding-rules.md`, which is now a
pointer to this file.

Each module's `AGENTS.md` file carries its own terse copy of the rules that apply to that
module — those stay in place as the fast-reference instructions an agent reads while working
in that directory. This document exists because that means the *reasoning* behind a rule is
scattered across ~25 files with no single place to read it end to end. Every entry below
states the rule, **why** it exists (the concrete vulnerability class or failure mode it
prevents), and the source `AGENTS.md` file so the two stay traceable to each other.

If you add, change, or remove a security-relevant rule in any `AGENTS.md` file, update the
matching entry here in the same change (see `docs/AGENTS.md`'s trigger table).

## How to read this document

- **Rule** — the constraint itself, usually copied near-verbatim from the source file.
- **Why** — the concrete failure mode or vulnerability class it closes off. Where the source
  `AGENTS.md` names a CWE, it's kept here too.
- **Source** — the `AGENTS.md` file that owns this rule day to day.

Rules are grouped by theme first (memory safety, secrets, cryptography, ...) since most
vulnerabilities cut across module boundaries; a per-module index follows at the end for
quickly finding everything a given `AGENTS.md` file contributed.

## Memory safety and resource ownership

- **Secret files must be owner-read-only (`0400`), not merely owner-only.**
  `platform::is_secure_secret_file()` rejects group and other access, execute bits, and
  owner-write. Applies to `security.secrets.master_key_file`, `database.uri_file`,
  `security.registration.token_file`, and every listener `tls_private_key_file`; a file
  failing the check aborts startup.
  Why: the service account is also the account a compromised worker process runs as. A
  writable master key lets an attacker who reaches code execution substitute a key of their
  own and then decrypt or re-sign at will, which turns a contained compromise into a
  federation identity takeover (CWE-732 Incorrect Permission Assignment for Critical
  Resource). The file is never written after provisioning, so `0400` costs nothing.
  Source: 0.12.5 security audit, finding 22; `docs/hardening.md`.

- **Outside `src/crypto/`, `src/events/`, `src/auth/` and `src/core/secret_buffer.cpp`, erase
  secret bytes with `core::secure_zero()` — never by calling `sodium_memzero` directly, and
  never by relying on a container's destructor.**
  Prefer `core::SecretBuffer` wherever the owning type can be move-only; `secure_zero` is for
  the cases where it cannot, such as a database row that has to stay copyable.
  Why: the crypto boundary exists so libsodium use stays auditable in four directories rather
  than the whole tree, and `scripts/reject-unsafe.sh` enforces it. A plain `clear()` or a
  destructor leaves the bytes in freed heap memory (CWE-226 Sensitive Information in Resource
  Not Removed Before Reuse), and a compiler is free to elide a hand-written zeroing loop
  entirely (CWE-14 Compiler Removal of Code to Clear Buffers).
  Source: 0.12.5 security audit, finding 17; `src/core/AGENTS.md`.

- **Release a request guard with `homeserver::ScopedGuardRelease`, not a manual
  `guard.unlock(); f(); guard.lock();` triple.** A manual release needs a
  `// LOCK_RELEASE: reviewed — <reason>` annotation or `scripts/reject-unsafe.sh` rejects it.
  Why: the RAII scope restores the guard on the exceptional path as well as the normal one,
  so a throwing outbound call cannot leave the locking invariant broken (CWE-667 Improper
  Locking). RAII is non-negotiable in this codebase; the annotation exists so the handful of
  legitimate exceptions — releasing before `notify_one`, or before calling a function that
  self-locks — are visible to a reviewer rather than indistinguishable from a regression.
  Source: 0.12.5 security audit, finding 14; `include/merovingian/homeserver/request_lock.hpp`.

- **RAII is non-negotiable.**
  Why: resources (file descriptors, locks, `SecretBuffer`s, mutex guards) must be released
  even when an exception unwinds through the function. A resource that only gets freed on
  the happy path leaks under error conditions — for file descriptors this is exploitable as
  resource-exhaustion DoS; for secret buffers it means key material never gets zeroised.
  (CWE-401 Missing Release of Memory, CWE-459 Incomplete Cleanup.)
  Source: root `AGENTS.md`, `security/coding-rules.md`.

- **No raw owning pointers — use smart pointers; prefer references over pointers.**
  Why: manual pointer lifetime tracking is the direct cause of use-after-free and
  double-free bugs, and a raw pointer can silently be null where a reference statically
  cannot. (CWE-401 Missing Release of Memory, CWE-416 Use After Free, CWE-476 NULL Pointer
  Dereference.)
  Source: root `AGENTS.md`, `security/coding-rules.md`.

- **No naked `new`/`delete`, no manual `malloc`/`free`/`calloc`/`realloc` outside reviewed
  low-level wrappers.**
  Why: manual allocation pairing is exactly the pattern that produces double-free and
  use-after-free bugs; smart pointers and containers make the pairing automatic and
  exception-safe. Enforced mechanically by `scripts/reject-unsafe.sh` as a pre-commit gate —
  if it blocks a change, fix the code, do not add an exception to the script. (CWE-415
  Double Free, CWE-416 Use After Free, CWE-401 Missing Release of Memory.)
  Source: root `AGENTS.md`, `scripts/AGENTS.md`, `security/AGENTS.md`, `security/coding-rules.md`.

- **`std::shared_ptr` requires justification** (an explicit `// SHARED_PTR: reviewed — <reason>`
  comment; `reject-unsafe.sh` enforces this).
  Why: shared ownership obscures who is responsible for lifetime and invites reference
  cycles or unexpectedly-extended lifetimes of secret-bearing objects. Requiring a reviewed,
  visible justification keeps shared ownership rare and auditable rather than a default.
  Source: `security/coding-rules.md`.

- **`FileDescriptor` (or `core::FileDescriptor`) must be used for all raw OS file descriptors
  — never store a bare `int` fd outside RAII scope.**
  Why: an fd that isn't RAII-owned can be leaked (resource exhaustion) or double-closed
  (which on some platforms silently closes an unrelated fd that was reused for a new
  resource, a classic fd-confusion bug).
  Source: `src/core/AGENTS.md`.

- **All sockets must be opened with `O_CLOEXEC` / `SOCK_CLOEXEC`. File descriptors must not
  leak across `fork()`/`exec()`.**
  Why: Merovingian spawns worker subprocesses (the federation worker via `posix_spawn`, the
  thumbnail worker via `fork()`) while client connections and other sockets may still be
  open. A socket without the close-on-exec flag is inherited by the child, handing a
  compromised or buggy worker process an unaudited handle onto connections it should never
  see — this was a real, fixed vulnerability (accepted client sockets in `http_server.cpp`
  were missing `SOCK_CLOEXEC` until the fix landed; see `docs/threat-model.md`).
  Source: `src/net/AGENTS.md`.

- **No unchecked narrowing conversions.**
  Why: an implicit narrowing conversion (e.g. `size_t` → `int`) can silently truncate a
  value an attacker controls (a length, a count, an offset), turning a bounds check upstream
  into a bypass downstream. (CWE-197 Numeric Truncation Error.)
  Source: `security/coding-rules.md`.

- **Ownership policy: prefer values; prefer references for required access; use
  `std::span`/`std::string_view` for bounded non-owning access; `not_null<T*>` only for
  unavoidable interop.**
  Why: this is the concrete decision order that keeps the "no raw owning pointers" rule
  achievable in practice — a non-owning view type (`span`, `string_view`) documents at the
  type level that the callee does not need to manage the referent's lifetime, which is what
  actually prevents the ownership-confusion bugs that raw pointers invite.
  Source: `security/coding-rules.md`.

## Secrets and logging

- **`SecretBuffer` must be used for any bytes that must not survive past their scope:
  tokens, private key material, passwords in transit.** It zeroes memory (`sodium_memzero`)
  on destruction even under exceptions, and `mlock`s the backing memory so it cannot be
  swapped to disk.
  Why: without this, secret bytes remain in freed heap memory until reallocated and
  overwritten — recoverable from a core dump, an unrelated arbitrary-read bug, or (without
  `mlock`) a swapped page. This is why the master-key loader and the crypto module's derived
  keys (`SecretBoxKey`, `TokenHmacKey`, `IpcAuthKey`) all wrap their bytes this way or
  zeroise on destruction — see `docs/crypto-boundary.md`.
  Source: `src/core/AGENTS.md`, `src/crypto/AGENTS.md`, `src/auth/AGENTS.md`.

- **Never log key material, tokens, passwords, or full request bodies.** Wrap sensitive
  data in `SecretBuffer`; truncate to a safe prefix (e.g. first 8 characters of a token) if
  identity is needed in logs; log `user_id`/`device_id`, not the token, for request traces.
  Why: log files are frequently retained far longer than a live secret's intended lifetime,
  shipped to third-party aggregators, or accessible to a wider set of operators than the
  production secret store — logging a secret is equivalent to leaking it. (CWE-532 Insertion
  of Sensitive Information into Log File.) A concrete instance of this rule being violated
  and fixed: the registration-token validity endpoint's `token` query parameter wasn't on the
  sensitive-marker redaction list and was logged in cleartext (see `docs/threat-model.md`).
  Source: `src/crypto/AGENTS.md`, `src/auth/AGENTS.md`, `src/observability/AGENTS.md`,
  `security/coding-rules.md`.

- **Never read config values directly from environment or disk inside other modules — all
  config access goes through `runtime_config.hpp`. Log the effective config at startup
  excluding secrets; never log TLS private key paths or secret values.**
  Why: centralizing config access means validation happens exactly once, in one reviewed
  place, instead of every call site re-implementing (and potentially getting wrong) parsing
  and bounds checks; logging startup config is valuable for diagnosing misconfiguration but
  must not become a secret-disclosure channel.
  Source: `src/config/AGENTS.md`.

- **Every new log call added to a security-sensitive path must be reviewed in
  `docs/observability-audit.md`.**
  Why: this is the process control that's supposed to catch a new accidental secret-logging
  call before it merges, rather than relying on someone noticing after the fact.
  Source: `src/observability/AGENTS.md`.

- **Security-relevant events must be emitted as structured audit log entries, not plain log
  lines**: login success/failure (with remote IP), token invalidation, rate-limit exceeded,
  federation request authenticated/rejected, media quarantine triggered.
  Why: an audit trail is what makes incident detection and after-the-fact investigation
  possible at all — a plain debug log line that happens to mention a security event is not
  reliably queryable or retained the way a structured audit row is.
  Source: `src/observability/AGENTS.md`.

- **Log lines must be structured and bounded; logging must not allocate unbounded
  attacker-controlled memory; logging paths must not bypass redaction requirements.**
  Why: a log call that formats an unbounded, attacker-influenced string (e.g. echoing a
  request body without a length cap) is itself a memory-exhaustion vector, and a log path
  that constructs its own output instead of going through the shared redaction helpers is a
  path where a future secret-logging bug is one missed `if` away.
  Source: `security/coding-rules.md`.

## Cryptography

- **Never call libsodium functions directly from outside the permitted crypto boundary**
  (`src/crypto/`, `src/events/`, `src/auth/`, and `src/core/secret_buffer.cpp`).
  Do not bypass the `Ed25519Provider` interface by calling libsodium directly, even inside
  those modules except where the module's own rules explicitly require it (e.g. `src/auth/`
  for password hashing, `src/core/secret_buffer.cpp` for `mlock`/`munlock`).
  Why: confining crypto primitive usage to reviewed modules means every use of a primitive
  has been checked for correct parameter order, correct buffer sizing, and correct error
  handling — the kind of mistake that turns a sound algorithm into a broken protocol. It
  also means the whole codebase has exactly one place to update when a primitive's API or
  security guidance changes.
  Source: `src/crypto/AGENTS.md`, `src/auth/AGENTS.md`, `src/core/AGENTS.md`.

- **Always use constant-time comparison for secrets.** Call `constant_time_equal()` from
  `crypto/constant_time.hpp`; never use `==`, `memcmp`, or `std::equal` on secret bytes —
  this includes access tokens, password hashes, and any other comparison against
  attacker-influenced input where the *comparison itself* is security-relevant.
  Why: an early-exit comparison (`==`/`memcmp` both are, in practice, on every common
  standard library implementation) leaks how many leading bytes matched via response timing,
  letting an attacker recover a secret byte-by-byte through repeated requests. Variable-length
  inputs additionally need domain-separated hashing before the constant-time compare, so the
  comparison doesn't leak the secret's *length* through an early size check.
  Source: `src/crypto/AGENTS.md`, `src/auth/AGENTS.md`.

- **Fail closed. If the signing key is unavailable, signing must fail — never fall back to
  an unsigned output or a weaker operation.**
  Why: a silent downgrade to unsigned data breaks the integrity guarantee every downstream
  consumer (federation peers, event authorization, state resolution) assumes holds — it's
  effectively is a signature-forgery bypass introduced by your own server rather than an
  attacker.
  Source: `src/crypto/AGENTS.md`.

- **Validate external key material and signatures before use** — call
  `ed25519_public_key_shape_is_valid()` / `ed25519_signature_shape_is_valid()` on anything
  received from a remote server; validate key IDs with `ed25519_key_id_is_valid()` (must
  start with `ed25519:`, printable non-space ASCII only).
  Why: passing attacker-controlled bytes of the wrong size or shape straight into a crypto
  primitive risks an out-of-bounds read/write inside the (typically C) crypto library, or at
  minimum an inconsistent/exploitable error path; malformed key IDs are a parsing-differential
  and injection vector if later embedded unescaped into other formats.
  Source: `src/crypto/AGENTS.md`.

- **Never sign or hash a string that was not produced by the canonical JSON serializer.**
  Any other JSON library, or ad-hoc string building, can produce non-canonical output that
  changes the hash of semantically identical content. Strip `signatures` and `unsigned`
  *before* serializing (via `signable.hpp`), not after.
  Why: Matrix event IDs, content hashes, and signatures are only meaningful if every party
  computes byte-identical canonical JSON for the same logical event — a non-canonical
  serializer breaks that equivalence, which is both a correctness bug and, if exploitable,
  a signature-malleability issue (the same logical content hashing to two different values
  depending on serializer quirks).
  Source: `src/canonicaljson/AGENTS.md`, `src/events/AGENTS.md`.

- **The canonical JSON serializer must reject floats on the signing/hashing path.**
  `serialize_canonical_strict()` (used by `event_signer.cpp`, `event_id.cpp`,
  `signable.cpp`) fails closed with `CanonicalJsonError::float_not_allowed` on a `Value` tree
  containing any double, rather than serializing one.
  Why: the Matrix canonical JSON spec forbids floats in signed/hashed data — integers only,
  within the JS-safe range. The general-purpose `serialize_canonical()` still accepts floats
  because it also serves ordinary, never-signed responses (e.g. `m.tag` `order`); without a
  dedicated strict entry point, a float-formatting bug in the shared serializer could
  silently corrupt a value that then gets hashed and signed as if it were correct (a
  fixed, real bug: `std::to_string(1e-7)` — fixed 6 fractional digits, not shortest
  round-trip — collapsed to `"0.0"` after trailing-zero stripping).
  Source: `src/canonicaljson/AGENTS.md`, `docs/canonical-json.md`.

- **The parser rejects duplicate object keys.**
  Why: JSON parsers disagree on which duplicate key wins (first vs. last), which is a
  well-known parser-differential attack vector — two implementations validating and then
  acting on "the same" JSON document can end up looking at different data if it contains a
  duplicate key.
  Source: `src/canonicaljson/AGENTS.md`.

- **Always hash tokens before storing** (`crypto_generichash(token)`); **tokens come from
  `crypto/random.hpp`**; **tokens are never stored or logged in plaintext.**
  Why: storing a raw token means a database read (backup leak, SQL injection, insider access)
  directly yields a usable credential; storing only a hash means the same breach yields
  nothing usable without also breaking the hash. Tokens must additionally have adequate
  entropy at generation time (CSPRNG, not a weak/predictable source) or the hash-of-secret
  protection is moot.
  Source: `src/auth/AGENTS.md`.

- **Argon2id for password hashing** (`crypto_pwhash` with `OPSLIMIT_INTERACTIVE` /
  `MEMLIMIT_INTERACTIVE`); **never SHA or bcrypt for passwords.**
  Why: SHA is fast by design (bad for password hashing — trivially brute-forced with GPUs/
  ASICs); Argon2id is memory-hard, deliberately expensive to parallelize on custom hardware,
  and is the current best-practice choice for password storage.
  Source: `src/auth/AGENTS.md`.

## Authentication and authorization

- **Always check the UIAA stage list from config before accepting an auth attempt.**
  Why: skipping a configured interactive-auth stage is a straightforward authentication
  bypass — the whole point of UIAA is that every configured stage must be satisfied before
  the sensitive action it protects (e.g. account deletion) is allowed.
  Source: `src/auth/AGENTS.md`.

- **`POST /refresh` must not require access-token authentication.**
  Why: per spec, `/refresh` authenticates via the refresh token in the request body, not an
  access token — and its entire purpose is recovering from an *expired* access token.
  Gating it behind a valid access token makes the endpoint unusable in the exact situation
  it exists for (a fixed, real bug — see `docs/threat-model.md`).
  Source: `src/auth/AGENTS.md`, `docs/auth-identity.md`.

- **Validate all user IDs against the identifier grammar before accepting registration.**
  Why: an unvalidated identifier can smuggle characters that break downstream parsing
  assumptions elsewhere in the codebase or in federation partners (injection/spoofing risk),
  or collide with a differently-encoded form of an existing user ID.
  Source: `src/auth/AGENTS.md`.

- **Authorization rules are room-version-aware — always pass the correct
  `RoomVersionPolicy`; never assume one room version's rules apply to another.**
  Why: authorization rules genuinely differ between room versions (e.g. restricted joins,
  redaction rule changes); applying the wrong version's rules can accept an event that
  should have been rejected under the room's actual rules, or vice versa.
  Source: `src/events/AGENTS.md`, `src/rooms/AGENTS.md`.

- **Authorization must be checked before persisting any locally-created event, and before
  accepting any inbound federation PDU.**
  Why: this is the single gate that keeps a room's membership and power-level state
  consistent with the rules every participating server is supposed to enforce; skipping it
  for even one code path lets an unauthorized event (privilege escalation, unauthorized
  membership change) into the room's permanent history.
  Source: `src/events/AGENTS.md`, `src/federation/AGENTS.md`.

- **Self-leave is only authorized when the sender's current membership is `invite`, `join`,
  or `knock`.** An unrecognized `membership` value on an event must be rejected outright,
  not defaulted to any known transition.
  Why: without the current-membership precondition, a *banned* user's self-leave event
  would be authorized, flipping their membership from `ban` straight to `leave` — from which
  they can rejoin or knock normally. This was a real, fixed ban-evasion bypass (see
  `docs/threat-model.md`); defaulting an unrecognized membership value to `leave` compounded
  it by admitting garbage membership content under the guise of a valid transition.
  Source: `src/events/AGENTS.md`.

- **Never construct an event ID manually — always use `event_id.hpp`.** Event ID format is
  room-version-dependent (legacy `$localpart:server` for v1–v2, reference-hash-derived for
  v3+).
  Why: a hand-constructed event ID that doesn't match the room version's actual derivation
  algorithm breaks the integrity link between an event's ID and its content — federation
  partners computing the ID correctly will disagree with yours, and (for v3+) an ID that
  isn't the actual reference hash defeats the purpose of using a hash as the ID at all.
  Source: `src/events/AGENTS.md`.

- **Never inline state resolution logic — always delegate to `state_resolution.hpp`'s v2
  algorithm implementation.**
  Why: state resolution is what keeps divergent copies of room state (e.g. after a network
  partition) converging to the same answer on every server; a divergent or partial
  reimplementation could let one server accept a different "winning" state than its peers,
  opening a state-forking attack.
  Source: `src/events/AGENTS.md`.

- **Never trim event fields manually for redaction — always use `redaction.hpp`'s
  room-version-specific algorithm.**
  Why: the redaction algorithm determines exactly which fields survive a redaction and is
  itself part of what gets hashed and verified; a manual/incorrect redaction can either
  leave sensitive content un-redacted or break the reference-hash verification that depends
  on the redacted form being exactly reproducible.
  Source: `src/events/AGENTS.md`.

- **`encryption_policy.hpp` is consulted before accepting a plaintext `m.room.message` event
  in a room with `m.room.encryption` state.**
  Why: this is the enforcement point that keeps an encrypted room actually encrypted — a
  path that skips this check would let a plaintext message slip into a room whose members
  and clients all assume every message is end-to-end encrypted.
  Source: `src/rooms/AGENTS.md`.

- **`RoomVersionPolicy` is the single authoritative source of which rules apply to a given
  room — obtain one before evaluating authorization, running state resolution, constructing
  event IDs, or applying redaction. Do not hard-code version-specific logic elsewhere.**
  Why: scattering version-specific `if (room_version == ...)` checks throughout the codebase
  is how a version-specific security rule silently stops being applied when the surrounding
  code changes — a single authoritative policy object is easy to audit and hard to
  accidentally bypass.
  Source: `src/rooms/AGENTS.md`.

## Federation (the highest-risk surface — all input comes from untrusted remote servers)

- **Authenticate every inbound request with X-Matrix auth before touching any body data.**
  Reject with `401` if the header is absent, malformed, or the signature is invalid.
  Why: processing a request body before verifying who sent it means unauthenticated,
  attacker-controlled bytes reach parsing/business logic before any trust decision has been
  made — the header check must be the very first gate, not a check performed alongside or
  after body processing.
  Source: `src/federation/AGENTS.md`.

- **Verify every inbound PDU's signature against the sending server's published key before
  it enters the event graph. Unverified events must be silently dropped, not persisted.**
  Why: without this, any peer (or a relay forwarding on another server's behalf) could
  inject events attributed to a user or server it doesn't control — this was a real, fixed
  vulnerability (`authorize_federation_pdu` originally skipped verification for relayed
  PDUs; see `docs/threat-model.md`, entries C1 and #270).
  Source: `src/federation/AGENTS.md`.

- **Fetch remote server keys via `remote_key_cache.hpp` — never trust a key the remote
  server supplies inline. The cache fetches from `/_matrix/key/v2/server` and enforces TTL.**
  A key past its `valid_until_ts` must not be used to authenticate a *new* PDU or request —
  the cache's stale-key fallback exists only so callers can distinguish "known but
  unreachable" from "never seen," not to authenticate new traffic.
  Why: trusting an inline key means an attacker who can inject any HTTP response can hand
  you a key of their own choosing and self-sign forged events; enforcing TTL prevents an
  indefinitely-lived compromised key from continuing to authenticate traffic after its
  owner rotated away from it (a real, fixed gap — see `docs/threat-model.md`).
  Source: `src/federation/AGENTS.md`.

- **Reject soft-failed events — do not forward or act on events that fail auth but are kept
  around for state-resolution purposes.**
  Why: soft-failed events are retained only because the state-resolution algorithm needs
  them for bookkeeping; treating them as acted-upon (forwarded to clients, used to authorize
  further events) would mean an event that explicitly failed the room's authorization rules
  still has a real effect.
  Source: `src/federation/AGENTS.md`.

## HTTP and network boundary

- **Rate limiting is applied before any auth check.** Do not move it after auth.
  Why: if rate limiting runs after authentication, an unauthenticated attacker can send
  unlimited requests that all fail auth cheaply but still consume server resources —
  rate-limit-before-auth is what actually bounds the cost of an unauthenticated flood.
  Source: `src/http/AGENTS.md`.

- **Header lookup must be case-insensitive** (`request_header(req, name)`); never index
  `req.headers[...]` directly.
  Why: HTTP header names are case-insensitive per spec; a case-sensitive lookup can miss a
  security-relevant header (an auth header, a `Content-Type` check feeding a MIME-sniffing
  decision) sent with different casing, silently falling through to a default that may be
  less strict.
  Source: `src/http/AGENTS.md`.

- **Route all outbound federation requests through `outbound_client.hpp` — no ad-hoc HTTP
  calls from other modules.**
  Why: the outbound client implements the Matrix server-discovery protocol including the
  SSRF-relevant private/loopback-address blocking; an ad-hoc HTTP call from elsewhere in the
  codebase bypasses that vetted path entirely.
  Source: `src/http/AGENTS.md`.

- **Accepted client sockets must be `SOCK_CLOEXEC`** (both the plain-HTTP and TLS accept
  loops use `accept4(..., SOCK_CLOEXEC)`).
  Why: see the general CLOEXEC rule under "Memory safety and resource ownership" above — this
  is the specific, previously-missed instance of it (fixed; see `docs/threat-model.md` and
  `docs/http-transport.md`).
  Source: `src/net/AGENTS.md`, `src/homeserver/AGENTS.md`.

- **Thread pool tasks must not throw — an escaped exception terminates the process. Wrap
  task bodies in `try`/`catch` and log the error.**
  Why: framed as a stability rule, but a process-wide crash triggerable by driving a worker
  task into an uncaught exception is a remotely-triggerable denial-of-service if the task's
  input is attacker-influenced; catching and logging turns a crash into a bounded, visible
  failure.
  Source: `src/net/AGENTS.md`.

- **Default request-body cap is `rt.limits.max_body_bytes` (64 KiB), applied at the top of
  the dispatch function. A new endpoint that accepts a larger body must explicitly opt out.**
  Why: an unbounded request body is a memory-exhaustion DoS vector; a default-deny cap means
  every new endpoint is safe unless someone deliberately widens it (and, per the media
  upload path, replaces the default cap with a different explicit one).
  Source: `src/homeserver/AGENTS.md`.

- **Never call `handle_local_http_request()` with a real, unwrapped client body.** The
  internal pipe-delimited format (`declared_mime|sniffed_mime|scanner_clean|bytes` for
  media) must be built by `client_server.cpp` — never constructed anywhere else — and the
  4th field's `|`-boundary logic depends on the first three fields never containing an
  unescaped `|`.
  Why: this internal format carries fields (`sniffed_mime`, `scanner_clean`) that downstream
  code trusts implicitly. Anything that lets an attacker influence those fields directly
  (e.g. a client-controlled `Content-Type` header containing `|`, spliced in unescaped)
  forges the scanner/MIME verdict the receiving code relies on — a real, fixed
  vulnerability (see `docs/threat-model.md`).
  Source: `src/homeserver/AGENTS.md`, `src/media/AGENTS.md`.

- **Never hold `HomeserverRuntime::mutex` across a blocking network call.** Wrap the call
  in a `homeserver::NetworkIoUnlock` scope (`homeserver/request_lock.hpp`) and keep every
  read and mutation of runtime state outside it.
  Why: that one mutex serialises every client-server request and every inbound federation
  transaction, so a network call held across it turns any remote server into a
  denial-of-service lever — accepting a TCP connection and then never answering is enough
  to halt the whole homeserver for the length of the timeout, and both a `/keys/query`
  naming a user on the attacker's server and any media reference pointing at it reach that
  path without privilege. Request signing must stay *inside* the lock: `OutboundCall::secret_key`
  borrows a span into the runtime's `SecretBuffer`.
  Source: `src/homeserver/AGENTS.md`.

## Database

- **Never interpolate values into SQL strings — always use prepared statements with bound
  parameters.**
  Why: string-interpolated SQL is the textbook SQL injection vector; bound parameters are
  parsed by the database driver as data, never as executable SQL syntax, closing the
  class entirely rather than relying on escaping discipline. `statement.hpp` enforces this
  mechanically.
  Source: `src/database/AGENTS.md`.

- **Never log raw query parameters that may contain tokens, passwords, or PII.**
  Why: the same secret-in-logs concern as everywhere else in this document, applied
  specifically to the database layer, where bound parameters routinely carry exactly this
  kind of sensitive value.
  Source: `src/database/AGENTS.md`.

- **Schema changes go in `migrations/`, not ad-hoc `ALTER TABLE` calls in application code.**
  Why: untracked schema changes can leave different deployments running different, unaudited
  schemas — including ones that never received a security-relevant column addition/removal
  that a migration would have applied consistently everywhere.
  Source: `src/database/AGENTS.md`.

- **Higher-level modules receive a `PersistentStore&` and must not downcast to a
  backend-specific type.**
  Why: downcasting to a specific backend (SQLite vs. PostgreSQL) breaks the abstraction that
  keeps backend-specific unsafe operations (e.g. a backend-specific raw-SQL escape hatch)
  from being reachable by unrelated modules that have no business using them.
  Source: `src/database/AGENTS.md`.

- **Migrations run exactly once, in ascending numeric order, and must never be modified
  after being applied to any environment — write a new migration instead. Never drop a
  column or table without explicit user approval. Always provide a `DEFAULT` when adding a
  `NOT NULL` column to an existing table.**
  Why: modifying an already-applied migration desynchronizes schema state across
  deployments that applied the old vs. new version — a correctness bug that can manifest as
  security-relevant state (e.g. a column meant to have been dropped silently isn't, in some
  environments). A `NOT NULL` column with no default fails the migration outright on
  existing rows, and dropping data is irreversible.
  Source: `migrations/AGENTS.md`.

## Media

- **MIME type is allow-listed** (`allowed_mime_types`) and **unknown types are quarantined
  by default** (`quarantine_unknown_mime = true`), not served directly.
  Why: default-allow on MIME type would let an attacker upload and later have served
  arbitrary content types (e.g. executable/script content) without any human review step;
  quarantining unknowns is a fail-safe default that limits the stored-content attack
  surface.
  Source: `src/media/AGENTS.md`.

- **Declared and sniffed MIME type must be derived independently — the client's
  `Content-Type` header must not be copied into both fields.**
  Why: the entire purpose of the declared-vs-sniffed mismatch check is catching an attacker
  who declares a benign, allow-listed type (e.g. `image/png`) while uploading actually
  dangerous content (e.g. HTML with an embedded `<script>`). If both fields are populated
  from the same untrusted header, the mismatch check compares a value to itself and can
  never fire — a real, fixed vulnerability (see `docs/threat-model.md`,
  `docs/media-repository.md`).
  Source: `src/media/AGENTS.md`.

- **The thumbnail worker runs as a separate, sandboxed process. Do not load image-decoding
  libraries in the main server process.**
  Why: image decoders (libpng, libjpeg-turbo, etc.) are a historically common source of
  memory-corruption vulnerabilities because they parse complex, attacker-controlled binary
  formats. Isolating decoding in a sandboxed worker with reduced privileges (seccomp,
  `setrlimit`, no filesystem/network access beyond stdio pipes) means a decoder exploit is
  contained to a throwaway process instead of the main server.
  Source: `src/media/AGENTS.md`, `docs/threat-model.md`.

## Platform hardening

- **Hardening is applied at startup, before any network socket is opened.**
  Why: this ordering closes the window during which the server would otherwise be reachable
  without seccomp/ASLR/other OS-level protections active — hardening that gets applied after
  the first socket opens is hardening that has a gap.
  Source: `src/platform/AGENTS.md`.

- **`hardening_self_check` must pass before serving requests — it aborts the process if a
  required control (seccomp, ASLR, stack canaries) is not verifiably active.**
  Why: a fail-open self-check (log a warning and continue) would mean a hardening
  regression silently ships to production; aborting is what makes "required" actually mean
  required.
  Source: `src/platform/AGENTS.md`.

- **If a new syscall needs to be allowed by seccomp, add it to the allow-list — do not
  disable seccomp as a workaround.**
  Why: disabling the sandbox to unblock a syscall reopens the entire kernel attack surface
  seccomp was closing, for the sake of one syscall that could instead be added narrowly.
  Source: `src/platform/AGENTS.md`.

- **File paths from config must be validated before use — never pass a user-supplied path
  to `open()`/`stat()` without validation.**
  Why: an unvalidated, attacker- or operator-influenced path is a path-traversal vector
  (`../../etc/shadow`-style) and, combined with a check-then-use gap, a TOCTOU vulnerability.
  Source: `src/platform/AGENTS.md`.

- **`elf_probe` binary-hardening failures (missing PIE/RELRO/NX/canaries) are logged at
  `WARN`, not suppressed, even though they don't abort.**
  Why: unlike the runtime self-check, these are build/link-time properties that can't be
  fixed by aborting a running process — but silently swallowing the warning would let a
  hardening regression in the build pipeline go unnoticed indefinitely.
  Source: `src/platform/AGENTS.md`.

## Sync

- **Use `stream_token.hpp` — never parse or construct sync tokens manually.**
  Why: a sync token is opaque, client-supplied input on every subsequent request; a
  hand-rolled parser is much more likely to mishandle a malformed or adversarial token than
  the single, reviewed implementation, and inconsistent construction risks producing a token
  that either desyncs the client or leaks stream-position information it shouldn't.
  Source: `src/sync/AGENTS.md`.

## Trust and safety

- **Never hard-code moderation decisions — all rules come from config or an
  operator-supplied policy file.**
  Why: moderation logic embedded directly in code is unreviewable by the operators who are
  accountable for it and can't be audited or changed without a code deployment; keeping it
  in config/policy makes the actual rules transparent and operator-controlled.
  Source: `src/trust_safety/AGENTS.md`.

- **Policy engine decisions are logged at `DEBUG` with the rule that triggered them.**
  Why: without this, there's no way to review why a specific moderation decision was made —
  essential for investigating both false positives (legitimate content blocked) and false
  negatives (abuse that should have been caught).
  Source: `src/trust_safety/AGENTS.md`.

## Packaging and deployment

- **Service files must drop privileges — the systemd unit and rc.d scripts must run
  merovingian as an unprivileged user (`merovingian` or `_merovingian`), never as root.**
  Why: running a network-facing service as root means any remote-code-execution
  vulnerability in the server is immediately a full host compromise, not just a
  compromise of the service's own limited privileges.
  Source: `packaging/AGENTS.md`.

- **The systemd unit must set at minimum `PrivateTmp=true`, `NoNewPrivileges=true`, and
  `ProtectSystem=strict`.**
  Why: these directives bound the blast radius of a compromised process — no privilege
  escalation via setuid binaries, no interference via shared `/tmp`, and a read-only view
  of the filesystem outside explicitly writable paths.
  Source: `packaging/AGENTS.md`, `docs/hardening.md`.

- **Do not hardcode installation paths — use the install prefix substituted at build time
  by `meson install`.**
  Why: a hardcoded path that doesn't match the actual install location can cause the server
  to load a file (a config, a library) from an unexpected, potentially attacker-writable
  location instead of the intended one.
  Source: `packaging/AGENTS.md`.

## Testing requirements for security-critical code

- **Auth, crypto, and token tests require negative-path scenarios**: reject invalid inputs
  (wrong size, wrong prefix, malformed), boundary values (zero-length, max-length,
  off-by-one), and error paths must not leak state or partial output.
  Why: security-critical code is disproportionately exercised by adversarial rather than
  well-formed input in production; a test suite that only covers the happy path gives no
  signal about how the code behaves under attack, which is precisely when it matters most.
  Source: `tests/unit/AGENTS.md`.

- **Any type marked thread-safe at runtime needs an actual concurrency test** (many threads,
  a release barrier so calls overlap, assert every call returns a valid result) — a comment
  saying "thread-safe" is not a substitute.
  Why: race conditions in shared security-critical state (session/auth state, rate-limit
  counters, key material) are exactly the kind of bug that doesn't show up without a test
  specifically designed to force concurrent access, and can manifest as TOCTOU-style
  authorization bypasses or corrupted secret state.
  Source: `tests/unit/AGENTS.md`.

- **Conformance tests must never have their assertions weakened, removed, or changed
  without citing the spec section that changed — a failing conformance test means the
  implementation is wrong, not the test.**
  Why: many conformance tests directly encode security-relevant Matrix spec requirements
  (auth rules, signing, redaction, X-Matrix auth); silently weakening one to make CI pass is
  equivalent to silently removing the security guarantee it was verifying.
  Source: `tests/conformance/AGENTS.md`.

- **Parsers that process untrusted/external input need fuzz coverage** (canonical JSON, HTTP
  requests, sync filters, config, stream tokens, query params, SRV records) —fuzzing asserts
  the parser does not crash, corrupt memory, or loop infinitely. **When a fuzz run finds a
  crash, the minimal reproducer becomes a permanent `[fuzz][regression]` unit test.**
  Why: any code that parses attacker-controlled bytes is a direct attack surface for
  memory-corruption and denial-of-service bugs; fuzzing is the practical way to find the
  edge cases a human wouldn't think to write a test for, and converting each crash into a
  permanent regression test prevents the same bug from being silently reintroduced later.
  Source: `tests/fuzz/AGENTS.md`, `security/coding-rules.md`.

- **Integration tests run clean under ASan/UBSan and TSan in CI.**
  Why: sanitizers catch memory-corruption and data-race bugs directly rather than relying on
  them manifesting as an observable test failure — many exploitable bugs never fail a
  correctness assertion but do trip a sanitizer.
  Source: `tests/integration/AGENTS.md`, `security/coding-rules.md`.

- **`tests/support/master_key.hpp`'s deterministic test key must never reach a non-test
  binary** — enforced by a `static_assert` that fires unless `MEROVINGIAN_TEST_BUILD` is
  defined.
  Why: a deterministic (fixed-seed) signing key is by definition not a secret — if it ever
  ended up compiled into a production binary, every server built from that binary would
  share the same, publicly-known-in-source signing key. The compile-time guard makes this a
  build failure instead of a silent, catastrophic misconfiguration.
  Source: `tests/support/AGENTS.md`.

## Process: how these rules are enforced and kept current

- **Every entry in the security rule set should reference a CWE number or a named
  vulnerability class where one applies** (most entries above do; a few — process/ordering
  rules like "rate limit before auth" — are named failure modes without a single CWE).
  Why: tying a rule to a concrete vulnerability class keeps the rule set grounded in real
  failure modes rather than accumulating "because we said so" style entries that are hard to
  evaluate for continued relevance.
  Source: `security/AGENTS.md`.

- **Changes to the security rule set require a security review comment in the PR.**
  Why: this is the gate that prevents an unreviewed weakening of a security rule from
  merging quietly alongside an unrelated change.
  Source: `security/AGENTS.md`.

- **`scripts/reject-unsafe.sh` enforces a subset of these rules automatically (banned
  patterns: raw `new`, `delete`, `malloc`, `free`, `calloc`, `realloc`,
  unjustified `shared_ptr`, direct libsodium calls outside the crypto boundary, and
  unannotated manual lock release) — a new rule that can be grep-detected should be added to
  that script.**
  Why: automated enforcement catches violations at commit time, before a human reviewer even
  sees the diff, which is strictly more reliable than relying on every reviewer to remember
  every rule in this document.
  Source: `security/AGENTS.md`.

- **Security defects block release; warnings are treated as errors at compile time.**
  Why: compiler diagnostics catch instances of several rule categories above (narrowing
  conversions, unused results, etc.) automatically — treating a warning as non-fatal means a
  caught instance of a banned pattern can still ship.
  Source: `security/coding-rules.md`.

- **No protocol feature ships without tests; no dependency is added without review.**
  Why: an untested protocol handler is exactly where CWE-20 (Improper Input Validation) and
  CWE-863 (Incorrect Authorization) surfaces hide, since Matrix protocol handling is
  reachable directly by untrusted federation input; an unreviewed dependency is a
  supply-chain risk (CWE-1104 Use of Unmaintained Third Party Components) — a vulnerability
  in a dependency becomes a vulnerability in Merovingian without anyone having decided to
  accept that risk.
  Source: `security/coding-rules.md`.

- **Performance work must not bypass validation, bounds checks, authorization, signature
  verification, redaction, logging controls, or policy enforcement.**
  Why: every item on that list is a security control, and "this is on a hot path" is not a
  justification for skipping one — a fast-path optimization that quietly drops a check is
  functionally identical to introducing the vulnerability that check exists to prevent.
  Source: `security/coding-rules.md`.

## Index by source `AGENTS.md` file

For finding everything a specific file contributed, without re-reading the whole document:

| Source file | Sections it contributed to above |
|---|---|
| root `AGENTS.md` | Memory safety and resource ownership |
| `security/AGENTS.md`, `security/coding-rules.md` | Memory safety; Secrets and logging; Cryptography; Process |
| `src/core/AGENTS.md` | Memory safety; Secrets and logging |
| `src/crypto/AGENTS.md` | Secrets and logging; Cryptography |
| `src/canonicaljson/AGENTS.md` | Cryptography |
| `src/auth/AGENTS.md` | Secrets and logging; Cryptography; Authentication and authorization |
| `src/events/AGENTS.md` | Cryptography; Authentication and authorization |
| `src/rooms/AGENTS.md` | Authentication and authorization |
| `src/federation/AGENTS.md` | Federation |
| `src/http/AGENTS.md` | HTTP and network boundary |
| `src/net/AGENTS.md` | Memory safety; HTTP and network boundary |
| `src/homeserver/AGENTS.md` | HTTP and network boundary |
| `src/media/AGENTS.md` | HTTP and network boundary; Media |
| `src/database/AGENTS.md` | Database |
| `migrations/AGENTS.md` | Database |
| `src/config/AGENTS.md` | Secrets and logging |
| `src/observability/AGENTS.md` | Secrets and logging |
| `src/platform/AGENTS.md` | Platform hardening |
| `src/sync/AGENTS.md` | Sync |
| `src/trust_safety/AGENTS.md` | Trust and safety |
| `packaging/AGENTS.md` | Packaging and deployment |
| `scripts/AGENTS.md` | Memory safety; Process |
| `tests/unit/AGENTS.md` | Testing requirements |
| `tests/conformance/AGENTS.md` | Testing requirements |
| `tests/fuzz/AGENTS.md` | Testing requirements |
| `tests/integration/AGENTS.md` | Testing requirements |
| `tests/support/AGENTS.md` | Testing requirements |

## Related documents

- [`threat-model.md`](threat-model.md) — the running log of specific vulnerabilities found
  and fixed; many entries above cite a specific fix logged there.
- [`crypto-boundary.md`](crypto-boundary.md), [`canonical-json.md`](canonical-json.md),
  [`auth-identity.md`](auth-identity.md), [`http-transport.md`](http-transport.md),
  [`media-repository.md`](media-repository.md), [`hardening.md`](hardening.md),
  [`observability-audit.md`](observability-audit.md) — capability notes for the modules
  referenced above, with implementation-level detail this document doesn't repeat.
- [`security-review-checklist.md`](security-review-checklist.md) — the pre-release
  verification checklist (a checklist of what to *check*, not a rule reference).
- [`coding-rules.md`](coding-rules.md) — style-only conventions (naming, include order,
  formatting) that are explicitly *not* security-relevant.
