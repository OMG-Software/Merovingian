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

- **Release a request guard with `homeserver::RuntimeLockRelease`, not a manual
  `guard.unlock(); f(); guard.lock();` triple.** A manual release needs a
  `// LOCK_RELEASE: reviewed — <reason>` annotation or `scripts/reject-unsafe.sh` rejects it
  (since 0.12.6 the gate matches `->unlock()` as well as `.unlock()`).
  Why: the RAII scope restores the guard on the exceptional path as well as the normal one,
  so a throwing outbound call cannot leave the locking invariant broken (CWE-667 Improper
  Locking) — and because `runtime.mutex` is recursive, it releases every level the calling
  thread holds rather than the single level a hand-written `unlock()` drops. A release that
  leaves an outer level held keeps the mutex locked for the whole of the "released" call;
  that shipped three times (`create_room` 0.12.1, `leave_room` 0.12.3,
  `invite_user_by_threepid` 0.12.6), each time reachable by an unprivileged client.
  RAII is non-negotiable in this codebase; the annotation exists so the handful of
  legitimate exceptions — releasing before `notify_one`, for instance — are visible to a
  reviewer rather than indistinguishable from a regression. Releasing before calling a
  self-locking function is no longer one of them: the callee's own scope handles it.
  Source: 0.12.5 security audit, finding 14; issue #487;
  `include/merovingian/homeserver/request_lock.hpp`.

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

- **Write log records only through `SingleLog`, and never remove the control-character
  escaping in `SingleLog::make_log_line`.** Every line is passed through
  `escape_log_controls`, so `\n`, `\r`, other C0 controls, DEL and UTF-8 C1 controls in a
  logged value appear as printable escapes and the record's own `\n` is its only line break.
  Do not write log data to `std::cout`/`std::cerr` directly, and do not pre-escape a value
  yourself (it would be escaped twice). Render structured field values with
  `render_log_field_value`, which redacts and then caps each value at 2048 emitted bytes
  (`...[truncated N bytes]`); never emit a client-controlled value uncapped.
  Why: logged values such as a login `identifier.user` or `device_id` are client-controlled;
  an unescaped newline forges a whole extra log record that downstream parsers and operators
  trust, and an escape sequence reaches the operator's terminal (CWE-117 Improper Output
  Neutralization for Logs). AUTH-9 in the 2026-09-29 security audit.
  Source: `src/observability/AGENTS.md`.

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

- **An audit event an unauthenticated client can trigger on every request must not write one
  durable row per request, and client-supplied audit text is bounded.**
  `access_token.rejected`, `rate_limit.exceeded` and `request.rejected` are admitted through
  `AuditRateGate` (10 rows per kind per 60 s; the rest counted and reported as `suppressed=<n>`
  on the next row); `actor`, `target` and `reason` are cut to 255 bytes on a UTF-8 boundary with
  invalid bytes and control characters replaced.
  Why: a durable, synchronous audit write per junk request under the runtime mutex hands a
  client with no credential control over the server's write rate, memory and table growth
  (CWE-400, CWE-770), and an unbounded or malformed attacker-supplied string in an audit row
  or log line is a memory-exhaustion and log-forging vector (CWE-117).
  Source: [ADR-0080](adr/0080-rate-cap-audit-rows-for-unauthenticated-rejections.md);
  `src/observability/AGENTS.md`.

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

- **A secret is checked and read through one descriptor; a derived-key cache takes the master
  key's identity and bytes from one open (`crypto::open_master_key_file`).**
  Why: checking a path and then opening it again, or taking a cache identity from one open and
  the key material from another, lets a file swapped in between be used: the TLS private key
  was loaded by path after its startup check, and a cache could hold a key derived from a
  different file than its identity described (audit ISO-7).
  Source: `src/crypto/AGENTS.md`.

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

- **A client action that is, or advertises, a state event is refused up front unless the user
  may send that state event (`homeserver::may_send_state_event`); joining the room is not
  enough.**
  Why: `/upgrade`, directory visibility and room aliases used to check membership only, so a
  power-level-0 member could create a replacement room, publish a room against its
  moderators' wishes, or take any alias on the server (audit CSAZ-12, ADR-0127).
  Source: `src/homeserver/AGENTS.md`.

- **A locally created `m.room.member` event is projected into the membership tables only by
  `persist_composed_event`, and the row follows current state.**
  Why: when each endpoint projected for itself, a ban sent through the state API changed room
  state but left the user listed as joined, able to rejoin (audit CSAZ-6, ADR-0126).
  Source: `src/homeserver/AGENTS.md`.

- **A `memberships` row and its invite change commit in the same transaction as the member
  event and its `current_state` row (`database::MembershipProjection`), never after it; startup
  reconciles the rows from current state before building the roster.**
  Why: written separately, a fault between the two left a durable ban with a row still saying
  `join`, and hydration made the banned user a member again on every restart (audit DB-4,
  ADR-0149).
  Source: `src/homeserver/AGENTS.md`.

- **Split a user ID, room ID or room alias on its FIRST `:`, through
  `auth::user_id_server_name` / `auth::identifier_server_name`; never `rfind(':')`.**
  Why: no localpart contains `:`, while a server name may (`host:port`). Splitting on the last
  `:` addressed members on ported servers to the port, so they never received events (security
  audit run-1).
  Source: `src/auth/AGENTS.md`.

## Federation (the highest-risk surface — all input comes from untrusted remote servers)

- **Authenticate every inbound request with X-Matrix auth before touching any body data.**
  Reject with `401` if the header is absent, malformed, or the signature is invalid.
  Why: processing a request body before verifying who sent it means unauthenticated,
  attacker-controlled bytes reach parsing/business logic before any trust decision has been
  made — the header check must be the very first gate, not a check performed alongside or
  after body processing.
  Source: `src/federation/AGENTS.md`.

- **Never charge a failed X-Matrix signature to the origin the request names.**
  Why: until the signature verifies, the claimed origin is whatever the sender wrote.
  Incrementing that origin's `consecutive_failures` (the original H-04 design) let three
  unauthenticated packets trip `remote_trust_policy` for a real peer and, because only an
  accepted request reset the count, lock it out until restart (FED-4). A bad signature is
  charged to the source network address instead (429 `M_LIMIT_EXCEEDED` beyond the
  budget), and the origin-level backoff is written only after a verified signature and
  decays after a 5-minute quiet period. See ADR-0081.
  Source: `src/federation/AGENTS.md`, `docs/adr/0081-failed-inbound-signatures-are-never-charged-to-the-claimed-origin.md`.

- **Verify every inbound PDU's signature against the sending server's published key before
  it enters the event graph. Unverified events must be silently dropped, not persisted.**
  Why: without this, any peer (or a relay forwarding on another server's behalf) could
  inject events attributed to a user or server it doesn't control — this was a real, fixed
  vulnerability (`authorize_federation_pdu` originally skipped verification for relayed
  PDUs; see `docs/threat-model.md`, entries C1 and #270).
  There is no exception for an event whose sender is on our own server: verify it against
  this server's own signing keys (current and retired, never fetched over the network) and
  drop it if the key is not one we hold. Events in a `send_join` response must also belong
  to the room being joined; drop any other entry before verifying or storing it.
  Why: the `send_join` path once kept own-domain events unchecked and stored each event
  under its own `room_id`, so a local user's remote server could rewrite the power levels
  of any local room (FED-1, ADR-0083).
  Source: `src/federation/AGENTS.md`.

- **Every path that admits a remote PDU also verifies a restricted join's authorising-server
  signature, with `federation::verify_join_authorising_server_signature`, after the sender
  check.** An `m.room.member` event carrying `join_authorised_via_users_server` must be validly
  signed by that user's server (rooms/v10.md rule 4.2.1); the auth rules only see that the
  signature is present. `/send` and `send_join` do it through the resolver overload of
  `authorize_federation_pdu`, worker relay, backfill and `filter_verified_send_join_events` (the
  state a resident returns when this server joins) call it directly. Any one valid signature
  from the authorising server satisfies the rule, so each listed key is tried, up to
  `max_authorising_signature_keys`: the signatures object is not itself signed, so a relaying
  server can add key IDs.
  Why: until 0.12.31 only `/send` and `send_join` checked it, so a compromised worker, or any
  remote server answering a history fetch, could get a forged restricted join stored
  (CWE-347 Improper Verification of Cryptographic Signature; security audit run-1, ADR-0171).
  Source: `src/federation/AGENTS.md`.

- **Check a sender's signature against every key ID it lists, never only the first, and
  bound the candidates.** Use `federation::authorize_federation_pdu_sender` or
  `verify_server_signatures_on_event`; candidates come from `signature_key_ids_for_server`:
  `ed25519:` IDs only, no repeats, each through the caller's admitted lookup, and an event
  listing more than `max_signature_keys_per_server` (4) is refused before any lookup. Unknown
  keys and keys expired before `origin_server_ts` are skipped; any other signature that does
  not verify refuses the event, and at least one must verify.
  Why: a first-match loop refused genuine events signed with a rotated key and let a relay
  make any event fail by listing a junk ID first; "any one verifies" accepts an event carrying
  an invalid signature by a published key, which the spec drops; an unbounded list lets one
  event force unbounded key fetches (CWE-347 Improper Verification of Cryptographic Signature;
  CWE-400 Uncontrolled Resource Consumption for the bound; conformance audit R05, ADR-0183).
  Source: `src/federation/AGENTS.md`.

- **This server co-signs a restricted join only after `homeserver::decide_restricted_join`
  authorises it, and every locally composed join naming a local authoriser passes the same
  decision.** The only exemption from the authorising-signature check is a `send_join` naming
  this server's user (`PduSignatureChecks::authorised_here`), because the acceptor signs it,
  after dropping every signature the joining server filed under this server's name. An allow
  condition is verifiable only while this server is joined to the room it names.
  Why: the auth rules check only that the named user is joined with invite power and that its
  server signed; whether the joining user met an allow condition is checked by nobody else, so
  signing without the decision lets anyone into a restricted room (CWE-863 Incorrect
  Authorization; conformance audit R04, ADR-0185).
  Source: `src/federation/AGENTS.md`, `src/homeserver/AGENTS.md`.

- **Never refuse a received event for a content-hash mismatch; redact it and continue.**
  Only a signature failure refuses (spec "Checks performed on receipt of a PDU", steps 2 and
  3). Everything after the check (authorisation, our signature, what is stored and returned)
  uses the redacted copy.
  Why: the direct membership endpoints refused a mismatch before the acceptor could redact it.
  Content the hash does not cover is unauthenticated, so only the redacted copy may be used
  (CWE-345 Insufficient Verification of Data Authenticity; conformance audit R06).
  Source: `src/federation/AGENTS.md`.

- **Fetch remote server keys via `remote_key_cache.hpp` — never trust a key the remote
  server supplies inline. The cache fetches from `/_matrix/key/v2/server` and trusts a key for
  at most 7 days after the fetch. From room v5 an event's signing key must be valid at the
  event's own `origin_server_ts`, not the current time; v1-v4 ignore `valid_until_ts`
  (ADR-0075).**
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

- **Main re-verifies every PDU a federation worker relays, with its own key resolver,
  before the runtime lock is taken, and builds the envelope from the verified event rather
  than the worker's framed fields.** A new worker-to-main relay that carries a PDU must do
  the same (`handle_pdu_ingest_request` in `src/homeserver/worker_pool.cpp` is the pattern).
  Why: the worker is the process most exposed to hostile input. Until 0.12.13 main trusted
  its signature check, so a compromised worker could inject events impersonating any
  sender the room authorised (ADR-0071, `docs/threat-model.md` #450).
  Source: `src/homeserver/AGENTS.md`.

- **A federation worker re-reads only public signing keys, and only on a miss.** The one
  table a worker reads after start-up is `server_signing_keys`, through
  `federation::KeyMirrorRefresh::on_miss`, for the server whose signature it is verifying.
  `database::refresh_remote_signing_keys` selects `server_name, key_id, public_key,
  valid_until_ts` and never `secret_key`, and is enabled only for the `federation_worker`
  load profile (`LocalDatabase::remote_signing_keys_read_through`). Do not widen that query,
  read other tables on demand, or give main's resolver the same flag.
  Why: only main writes those rows, after verifying the key and capping it at seven days, so
  the worker trusts nothing it did not already trust at start-up; a wider read would hand the
  most exposed process data it has no need for (ADR-0263).
  Source: `src/federation_worker/AGENTS.md`.

- **Every room-scoped federation read checks that the authenticated origin is in the room.**
  `GET /state`, `/state_ids`, `/event`, `/backfill` and `POST /get_missing_events` take the
  X-Matrix-verified `origin` (never a value from the request) and answer `403 M_FORBIDDEN`
  with no room data unless `federation::origin_may_read_room` holds: the room's CURRENT
  state has a `join` member on that server, or its current `m.room.history_visibility` is
  `world_readable`. The check is in the provider (`src/federation/event_query.cpp`), so it
  runs in whichever process serves the endpoint (the federation worker from its room
  snapshot, main for `/event`). It runs before the event or the request body is looked at,
  and an unknown room answers 403 rather than 404 so room existence is not disclosed. A new
  room-scoped read endpoint must take the origin and call this gate. `/state` and
  `/state_ids` answer 404 for an `event_id` that is unknown or in another room (no fallback
  to current state); `get_missing_events` walks back from `latest_events`, caps `limit` at
  20, caps `latest_events` at 100 and bounds its lookups.
  Why: until 0.12.15 the only gate was the server ACL, so any federating server that knew a
  room ID could dump the state, member list and full history of a private room
  (`docs/threat-model.md`, "Federation reads not limited to servers in the room").
  Source: `src/federation/AGENTS.md`.

- **Never relay a remote server's answer about users to a client unfiltered. Keep only
  the users you asked that server about, and only records that describe the user they are
  filed under.** For E2EE keys, go through `federation::accept_remote_key_query_response()`.
  Why: a client takes a master key it is shown as that user's cross-signing identity. A
  server answering a query for its own user could otherwise also answer for a user on any
  other server and have its keys accepted as theirs. Before 0.12.10 the `/keys/query` proxy
  passed through every user ID in the response (see `docs/threat-model.md`, "A remote server
  injecting E2EE identities").
  Source: `src/federation/AGENTS.md`.

- **An inbound EDU's identity claims belong to the sending server: bind the `sender` /
  `user_id` to the origin, deliver only to local users, de-duplicate by `message_id`, and
  cap what one EDU can write.** `m.direct_to_device` requires `sender` on the origin, targets
  only local active users, keeps a bounded `(origin, sender, message_id)` replay window (recorded only after the
  EDU's messages commit together) and queues at
  most 1 000 messages per EDU; `m.device_list_update` / `m.signing_key_update` record a
  change only for local users who share a joined room with the subject, as one batched write
  with one row per (observer, subject).
  Why: until 0.12.15 a peer could deliver verification and key-request to-device messages
  that appeared to come from any user, fill the queue with invented targets, and write one
  `device_list_changes` row per local user per EDU (audit FED-3, FED-7).
  Source: `src/federation/AGENTS.md`.

- **Authorise an inbound `/invite` for a room we hold against the room's current state before
  signing it, never overwrite a `ban` from that path, and leave `current_state` to the
  transaction path.** The URL event ID must equal the event's own reference-hash ID.
  Why: the endpoint used to rewrite a banned user's membership to `invite` and store the
  forged event as their state, so the ban could be undone by any remote server (audit FED-5).
  Source: `src/federation/AGENTS.md`.

- **Main's `accepted_transactions` ring is the record of completed `/send` transactions,
  whichever process ran them.** A path that runs an inbound transaction outside main's handler
  records its completions there (`record_completed_federation_transaction`) and sends a
  transaction already there to main.
  Why: each process kept its own ring, so a retry that reached main after the worker completed
  it (a room whose reload failed) was processed again and its EDUs delivered twice (OpenBSD CI,
  ADR-0160).
  Source: `src/federation/AGENTS.md`.

- **A room's version is read only through `homeserver::stored_room_version` /
  `stored_room_version_policy` (or `declared_room_version` for a create event in hand), and a
  federated join is refused unless the create event declares the make_join version.** A create
  without `room_version` is version 1, which has no policy; never substitute a default.
  Why: components each derived the version with their own default, so a resident server could
  seat a local user in a room judged under different rule sets by different components (ADR-0179).
  Source: `src/homeserver/AGENTS.md`.

- **Gap recovery for a PDU asks only for what the spec lets a peer serve, in the spec's terms,
  and stores nothing until it has what it needs.** `/get_missing_events` takes the PDU itself as
  `latest_events` and this room's forward extremities as `earliest_events`; a snapshot's named
  events are all fetched with `GET /event/{eventId}` before any is stored, and `/event_auth` is
  only the last resort for one event; held PDUs live in memory for one recovery and are verified
  again when placed; an event whose resolvable `auth_events` are disallowed, rejected or deny it
  is stored `rejected`, never dropped, and an unresolvable auth event stays a gap.
  Why: the reversed `/get_missing_events` arguments and the dependence on `/event_auth` left a
  PDU unplaced for ever against any peer that serves only the required endpoints, and dropping a
  rejected-auth outlier left every later event that named it unplaced.
  Source: `src/homeserver/AGENTS.md`.

- **Every outbound destination holds a bounded share of the dispatch queue, and every queued
  transaction has its own transaction ID. Never discard `DispatchWorker::enqueue`'s result.**
  Why: one dead or hostile peer filled the shared queue and starved every other peer; a shared
  transaction ID collapsed a fan-out into one durable row (CWE-400; ADR-0177).
  Source: `src/federation/AGENTS.md`.

## Application Service API

- **`as_token`/`hs_token` live in `core::SecretBuffer` and are never logged;
  compare them with `crypto::constant_time_equal`, never `==`.** The
  `hs_token` must stay reversible (it is transmitted to the appservice) so it
  cannot be stored as a hash the way access tokens are.
  Why: these are long-lived bearer credentials shared with an external
  process; the same secret-handling and timing-side-channel concerns that
  apply to access tokens apply here.
  Source: `src/appservice/AGENTS.md`.

- **Namespace regexes are matched with `std::regex_match`, never
  `std::regex_search`.** A namespace pattern is a claim over a whole
  identifier, not a substring.
  Why: under an unanchored search, the spec's own example namespace
  `@_irc_.*` also matches `@evil@_irc_bob:example.org` — letting one
  appservice's *exclusive* namespace claim, and so block registration of, an
  unrelated local user whose ID merely contains the pattern as a substring.
  Source: `src/appservice/AGENTS.md`.

- **Registration `id` and `as_token` must be unique per appservice, and
  namespace-exclusivity conflicts must fail the whole registration set
  closed.** `validate_registrations()` enforces both at boot.
  Why: two registrations sharing an `id`/`as_token`, or two appservices both
  exclusively claiming an overlapping namespace, is an ambiguity that has no
  safe resolution by load order — refusing to start is safer than guessing
  which registration should win.
  Source: `src/appservice/AGENTS.md`.

- **A namespace regex is compiled once, when `appservice::Namespace` is built. Request paths
  match against the compiled form and never compile a pattern.**
  Why: namespace matching runs for every member of every room an event reaches, under the
  runtime lock. Compiling the regex on each match multiplied that cost (CWE-407; security
  audit run-1, `sp02.appservice-regex-compile-under-mutex`).
  Source: `src/appservice/AGENTS.md`.

- **The events queued for one appservice are capped (`appservice.max_queued_events`), and a refused event
  is counted, logged and audited, never silent.** `enqueue_appservice_delivery` skips an appservice
  whose queue is at the cap, increments `appservice_outbox_dropped`, and reports the first refusal and
  every thousandth after it at warning level (which writes an `appservice.outbox.full` audit row
  naming the appservice).
  Why: the outbox of a bridge that never returns would otherwise grow with all the traffic of every
  room it is interested in, without bound, in the database and in memory (CWE-770; ADR-0191).
  Source: `src/homeserver/AGENTS.md`, `src/appservice/AGENTS.md`.

- **Ephemeral data for an appservice is in memory, coalesced by key and bounded, and its
  per-update work is budgeted.** At most 512 items per appservice, 100 per transaction, and 20000
  member-against-namespace matches per presence update (finding the subject's rooms is not charged, so
  rooms the subject is not in cannot use the budget up).
  Why: typing, receipts and presence arrive far more often than events, from federation too; an
  unbounded or per-member-per-update cost under `runtime.mutex` is a denial of service (CWE-400;
  ADR-0190).
  Source: `src/homeserver/AGENTS.md`.

- **Presence answers the same for a user who does not exist as for one the caller may not see, and an
  inbound `m.presence` EDU is kept only for a user of its origin who shares a joined room with a local
  user.** `read_presence` answers 403 for both; `accept_inbound_presence` looks at the first
  `max_inbound_presence_entries` (100) entries, refuses a `presence` outside the enumeration and a
  `status_msg` over 1024 bytes, and does one pass over the memberships per EDU, not per entry.
  Why: a 404 for a missing user would let any caller enumerate accounts, and unbounded rows keyed by
  a remote server's invented users would grow memory and the database without limit (CWE-204,
  CWE-770).
  Source: `src/homeserver/AGENTS.md`.

- **The appservice ping takes a slot in the client-outbound budget before its outbound call**, as the
  `/thirdparty/*` lookups do (ADR-0181).
  Why: it holds a request-pool thread for up to the appservice timeout (ADR-0079).
  Source: `src/homeserver/AGENTS.md`.

## Identity Service client

- **Every Identity Service host must resolve to SSRF-safe pinned addresses via
  `federation::CachedServerDiscovery`'s `deny_ip_ranges` — never an ad-hoc DNS
  lookup, and never a client-supplied address.** Fail closed when resolution
  yields no usable address.
  Why: an Identity Service base URL is operator configuration, but the
  resolution path must still not trust whatever DNS or a client hands back —
  the same private/loopback SSRF class applies here as to any other outbound
  call the homeserver makes on a user's behalf.
  Source: `src/identity/AGENTS.md`.

- **Identity Service base URLs must be `https://`; never send the homeserver's
  signing key or an `Authorization: X-Matrix` header to an Identity Service.**
  Authenticated calls use the client's bearer `id_access_token` instead.
  Why: an Identity Service is a client-facing trust boundary, not a federation
  peer — handing it federation signing material or credentials would expose
  them to a party the Matrix trust model never intended to hold them.
  Source: `src/identity/AGENTS.md`.

- **A 3PID is proven to belong to the caller only by a trusted Identity Service
  saying so (`getValidated3pid`); this server never marks a validation session
  validated itself.** A `requestToken` with no trusted `id_server` is refused, a
  delegated session starts unvalidated, and `/account/3pid/add`, `/bind` and
  `/account/3pid` bind nothing until the identity server reports the same medium
  and address validated.
  Why: the server cannot send email or SMS, so a session it validated itself
  would let a user bind an address they do not own (AUTH-5), after which the
  real owner is refused `M_THREEPID_IN_USE`.
  Source: `src/identity/AGENTS.md`, `docs/auth-identity.md`.

- **An `id_access_token` is validated at the client-server boundary before it is forwarded
  (`identity::id_access_token_is_valid`: printable ASCII, no space, at most 4096 bytes).** A violation is
  `400 M_INVALID_PARAM`; no identity-server call is made. This is in addition to the outbound client's
  own header check (ADR-0180), which stays the control every outbound header passes.
  Why: the token arrives as a JSON string, so after unescaping it can hold CR and LF, and it becomes the
  `Authorization` header of a call to the identity server (CWE-113; security audit run-1,
  `sp02.is-token-crlf-header-injection`).
  Source: `src/identity/AGENTS.md`.

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

- **One documented exception: Application Service transaction delivery is not
  SSRF-filtered.** `appservice::AppserviceClient` (`src/appservice/
  appservice_client.cpp`) resolves an appservice's `url` directly and sets
  `OutboundRequest::allow_cleartext_http = true`, bypassing
  `CachedServerDiscovery`'s private/loopback rejection and permitting plain
  `http://`. Do not generalize this pattern to any other outbound client.
  Why: an appservice `url` comes from an operator-placed registration file
  (`appservice.registration_files`), not network-reachable input, and most
  real-world bridges run as plain HTTP on `127.0.0.1` — the SSRF-safe path
  would make them unreachable. See `docs/threat-model.md`, "Outbound
  Application Service API transaction delivery" for the full justification
  and the condition under which this exemption must be revisited.
  Source: `src/appservice/AGENTS.md`; `docs/threat-model.md`.

- **`security.federation.allow_private_ip_ranges` reaches federation callers
  only.** `discover_server`, well-known fetches, `CachedServerDiscovery::discover`,
  the inbound origin check and the remote media re-check apply it.
  `resolve_federation_destination` applies it only when the caller passes it,
  and `CachedServerDiscovery::lookup_addresses_filtered` never does. A new
  outbound caller that fetches a client- or user-chosen URL (preview, redirect,
  pusher, identity server) must not pass it. Test any range check through
  `federation::ip_address_in_allowed_private_range`, which ignores a range
  `config::private_ip_range_is_allowable` refuses.
  Why: the allowance exists so federation can reach Docker or LAN peers
  (ADR-0231). Every caller that shares the discovery network would otherwise
  inherit an SSRF opening that was meant for server-to-server traffic only.
  Source: `src/federation/AGENTS.md`.

- **A URL a client names is fetched only through the URL preview gate
  (`gated_fetch` in `src/homeserver/url_preview_service.cpp`).** It resolves and checks every
  hop, redirects and images included, pins the connection to the checked addresses, and follows
  redirects itself. Its use of `allow_cleartext_http` is the second, and last, sanctioned one: the
  request carries no credential and the address pin applies to cleartext too. Every failure to
  fetch the target (refused address, unknown name, timeout, size, redirects, HTTP error) answers
  the same `502 M_UNKNOWN`. Answers given before any fetch keep their own status and say nothing
  about the target: `400` for bad parameters, `404` while previews are disabled, `429` from the
  rate limit or admission caps (the full list is in `docs/media-repository.md`).
  Why: a client-named URL is the classic SSRF vector; checking only the first hop, letting the
  HTTP client follow redirects, or resolving twice (DNS rebinding) each reopens it, and distinct
  errors turn the endpoint into an internal-network oracle (ADR-0213).
  Source: `src/homeserver/AGENTS.md`.

- **An upload's `filename` is validated at upload (`400 M_INVALID_PARAM` when
  `media::media_filename_is_valid` refuses it), so what is stored is what the client sent.**
  Why: the spec requires the download to carry the same filename, and a stored name later lands in
  a response header, where a CR or LF would split the response (CWE-113 Improper Neutralization
  of CRLF Sequences in HTTP Headers) (ADR-0211).
  Source: `src/media/AGENTS.md`.

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
  in a `homeserver::RuntimeLockRelease` scope (`homeserver/request_lock.hpp`) and keep every
  read and mutation of runtime state outside it.
  Why: that mutex guards client-server request state and narrower inbound-federation
  setup/callback scopes, so a network call held across it turns any remote server into a
  denial-of-service lever — accepting a TCP connection and then never answering is enough
  to halt the whole homeserver for the length of the timeout, and both a `/keys/query`
  naming a user on the attacker's server and any media reference pointing at it reach that
  path without privilege. Copy the signing secret into an owned `core::SecretBuffer`
  before the scope opens and move it into `OutboundCall::secret_key`; the call owns
  the key and signs after the mutex is released (ADR-0086).
  Source: `src/homeserver/AGENTS.md`.

- **A client request that makes this server call another one takes a slot in the
  client-outbound budget first, and runs under a short total deadline.** Take it with
  `homeserver::admit_client_outbound_proxy` (key: `rate_limit_client_key`), answer `429
  M_LIMIT_EXCEEDED` with `retry_after_ms` when it is refused, hold the slot until the call has
  ended, and draw discovery and every request from one `OutboundDeadline`
  (`homeserver/client_outbound_proxy.hpp`). Remote media additionally checks
  `security.media.remote_fetch_enabled` and `allow_remote` before any discovery.
  Why: releasing the runtime mutex frees the mutex, not the thread; `publicRooms?server=`, a
  remote alias lookup and remote media are reachable without authentication, and a peer that
  never answers pinned all 8 request-pool threads (audit HTTP-2, OUT-7; ADR-0079). The caps are
  half of `server.http.request_threads`, never a separate setting. The `/thirdparty/*` lookups
  take the slot too, whenever they will call an appservice, but keep each appservice's own timeout
  rather than one shared deadline (ADR-0181). The space hierarchy takes the slot at the first
  child room it must ask another server for, holds it for the whole walk, and bounds the walk to
  16 remote requests and 3 servers per room.
  Source: `src/homeserver/AGENTS.md`.

- **Nothing may put a TLS client socket back into blocking mode after the handshake, and
  no code below the HTTP layer may perform a blocking I/O call on a connection
  descriptor.** Drive `SSL_read`/`SSL_write` through a non-blocking retry loop
  (`WANT_READ`/`WANT_WRITE`) against an explicit deadline instead of a raw blocking call.
  Why: every timeout in the HTTP layer is expressed as `poll()` on the raw descriptor,
  which is only a real timeout if nothing beneath it can block. `poll(POLLIN)` proves TCP
  bytes arrived, never that a complete TLS record did — a blocking `SSL_read` entered on a
  socket holding a partial record can hang in the kernel indefinitely, past every deadline
  the server believes it is enforcing, parking one worker thread for as long as the
  attacker holds the connection open.
  Source: [ADR-0054](adr/0054-tls-sockets-stay-non-blocking-for-the-life-of-the-connection.md).

- **No worker thread may wait on a connection with nothing to read.** Waiting for a first
  byte or the next keep-alive request is the connection dispatcher's job
  (`homeserver::HttpConnectionDispatcher` over `net::ConnectionParker`); a request round
  that has written its response hands the connection back rather than waiting on it. A
  connection is dispatched only when readable, at most one per worker and at most
  `max(1, request_threads / 4)` per client address (trusted proxies exempt), and it is owned
  by exactly one of the dispatcher, one pool task, one sync-pool task or one
media-fetch-pool task.
  Why: a worker tied to its connection through idle and partial-read phases let one client
  hold the whole pool with eight sockets — kept alive with one request every idle − 1
  seconds, trickled bodies, or connects that never send a byte (audit HTTP-1, ADR-0077).
  Source: `src/net/AGENTS.md`, `src/homeserver/AGENTS.md`.

- **Request bodies are read under a minimum rate, and a large upload only after its head
  authenticates.** After a 10 s grace the body must have delivered 16 KiB/s × (elapsed −
  10 s) or the round ends with 408; the media upload routes read beyond the 1 MiB transport
  cap only once `media_upload_authentication_refusal` has accepted the access token, and
  otherwise answer 401 from the head and close. A new route that accepts a large body gets
  the same pre-body authentication.
  Why: a whole-body deadline with a 5 s inter-byte gap let one byte every 4.9 s hold a worker
  for most of an hour on an unauthenticated 50 MiB upload (audit HTTP-1, HTTP-6; ADR-0077).
  Source: `src/homeserver/AGENTS.md`, `src/http/AGENTS.md`.

- **Rows a user can add, and that requests scan under the runtime lock, are capped per user.**
  A new global account-data type past `server.client_api.max_global_account_data_per_user` is
  refused with `400 M_TOO_LARGE`; an update to a type the user holds is always allowed. Room
  account data is written only for a room the user holds a membership in, and a new type past
  `server.client_api.max_room_account_data_per_room` in that room is refused the same way. The
  `m.tag` and `m.fully_read` rows the tags and read-marker APIs write count towards that cap but
  are never refused by it, so tagging and read markers keep working at the cap (ADR-0197).
  Caps refuse, never evict (ADR-0118).
  Why: account-data reads scan every row under the lock, so one user adding types without bound
  slowed every request that reads them (CWE-770; security audit run-1, ADR-0173). Room rows
  multiply by rooms, so they need both bounds (conformance audit R10, ADR-0197).
  Source: `src/homeserver/AGENTS.md`.

- **The outbound client refuses a header name that is not an RFC 9110 token, or a value with a
  control character other than HTAB, before any network I/O (`OutboundError::invalid_header`).**
  Why: header values carry client-supplied data, and libcurl writes header lines verbatim, so
  CR/LF added header lines (CWE-113; ADR-0180).
  Source: `src/http/AGENTS.md`.

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

- **Every write to a `BLOB` column sets `BoundValue::binary`; reads decode every `bytea`
  result column generically.**
  Why: on PostgreSQL a text-bound binary value truncates at a NUL or is rejected as
  non-UTF-8, and an undecoded `bytea` read returns its hex text. Either breaks
  `server_signing_keys.secret_key`, after which the server cannot load its own signing
  key (0.12.14 audit, DB-1).
  Source: `src/database/AGENTS.md`.

- **Nothing in the process opens a SQLite database file except SQLite: check it by name
  (`fstatat` with `AT_SYMLINK_NOFOLLOW`) or read it through SQLite's own handle
  (`SQLITE_FCNTL_FILE_POINTER`).**
  Why: closing any descriptor of a file releases every POSIX lock the process holds on it.
  A check that opened and closed the database released another connection's write lock, so
  another process took the live transaction's journal for a hot one and could roll it back
  (PR #509 CI, ADR-0157).
  Source: `src/database/AGENTS.md`.

- **A read on a read-only SQLite connection prepares through `prepare` and steps through
  `first_step`, never a bare `sqlite3_prepare_v2` or first `sqlite3_step`.**
  Why: a writer committing between SQLite's two hot-journal checks makes a read-only
  connection fail with `SQLITE_READONLY_ROLLBACK`, skipping the busy handler. Those helpers
  retry it for up to 2 s; without them the federation worker's room reload failed on OpenBSD
  and the room fell back to main (ADR-0159).
  Source: `src/database/AGENTS.md`.

- **A read that combines several tables into one picture of a room runs in one read
  transaction** (`SqliteReadTransaction`; `REPEATABLE READ READ ONLY` on PostgreSQL).
  Why: the worker's room reload read each table separately, so a commit between two reads
  gave it state (an ACL, a membership) naming an event its snapshot did not hold, a room
  main never committed (ADR-0161).
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

- **The whole schema is one v1 migration, frozen from 1.0.0; a ledger naming a migration
  this build does not have is refused before anything is migrated or read, and every DDL
  path on PostgreSQL, the fresh-database bootstrap included, runs as
  `database.migration_role` when one is configured.**
  Why: a version number alone cannot tell this build's schema from another's (every
  pre-1.0 build wrote a v1 row too), so a database whose ledger is not this build's is
  refused rather than read through queries written for different tables. A bootstrap run
  as the login role would execute DDL with the widest privileges in the deployment and
  leave the migration role owning nothing, so the next migration could not `ALTER` the
  tables it must change.
  Source: [ADR-0224](adr/0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md);
  `src/database/AGENTS.md`, `migrations/AGENTS.md`.

- **Revocation is one-way: no function in the database layer may clear a `revoked`
  flag.** A requirement of the shape "revoke every token except this one" must be
  expressed as a narrower revoke (e.g. `revoke_tokens_for_user_except_device`), never
  as a broad revoke followed by a restore.
  Why: a restore primitive that exists to undo a revoke is indistinguishable, at the
  call site, from one that undoes an *intentional* one — a revoke-then-restore-the-
  caller's-device sequence used by password change once un-revoked every token ever
  revoked for that device, including ones revoked days earlier by an unrelated logout
  or admin action, handing an attacker's already-revoked token back at the exact
  moment (a password change after a compromise) the user is trying to invalidate it.
  Making the unsafe sequence unrepresentable, rather than merely unused, is what closes
  the class rather than the one instance.
  Source: [ADR-0052](adr/0052-revocation-of-credentials-is-one-way.md); `src/auth/AGENTS.md`.

- **Never retain committed statements in production; in-memory mirrors of append-only tables
  are bounded windows.** Statement capture is opt-in, bounded and off by default;
  `PersistentStore::audit_log` keeps only the newest 1 024 rows.
  Why: a committed statement's parameters include password and token hashes, so retaining
  every one keeps those hashes resident for the life of the process and grows memory with
  every write (CWE-316, CWE-770); an unbounded mirror of an append-only table lets any write
  path become a memory-exhaustion path.
  Source: `src/database/AGENTS.md`.

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

- **A federation media `multipart/mixed` boundary longer than 70 characters is refused, and
  delimiters are found with a linear scan.**
  Why: a remote server chooses the boundary and the body, and the parse runs under the runtime
  lock. Comparing the boundary at every offset made a long, repetitive boundary cost
  O(body × boundary) (CWE-407; security audit run-1, ADR-0176). RFC 2046 §5.1.1 limits a
  boundary to 70 characters.
  Source: `src/homeserver/AGENTS.md`.

- **The localpart `remote-media` is the server's own (`auth::localpart_is_reserved`), and remote
  media is told apart by `LocalMediaRecord::from_remote_fetch`, never by its owner string.**
  Why: a local account with that name imitated the remote media owner and escaped local quotas
  (ADR-0178).
  Source: `src/media/AGENTS.md`.

- **A file name reaches `Content-Disposition` only through `media::media_content_disposition`,
  which leaves out a name `media::media_filename_is_valid` refuses and encodes the rest.**
  Why: the name comes from a client (or a remote server) and is written into a response
  header; a CR or LF in it would split the response (CWE-113 Improper Neutralization of CRLF
  Sequences in HTTP Headers) (ADR-0211).
  Source: `src/media/AGENTS.md`.

- **A download that waits for a pending upload is admitted before it waits: at most
  `media_fetch_threads - 1` waits at once (none with a single worker) (half for one requester),
  and an ADR-0079 slot when it waits on a request thread; otherwise it answers
  `504 M_NOT_YET_UPLOADED` at once.**
  Why: a wait holds a worker for up to 20 s, and a client can create pending IDs freely; uncapped
  waits fill the media fetch pool and starve remote fetches, or hold main-pool workers with no
  admission (CWE-770 Allocation of Resources Without Limits or Throttling) (ADR-0212).
  Source: `src/homeserver/AGENTS.md`.

## Platform hardening

- **Check a sequence of irreversible restrictions in full before its first step.**
  OpenBSD `unveil(2)` calls are planned by `openbsd_unveil_rules()`, and none is made unless
  every path, or the directory it would be created in, exists.
  Why: the first `unveil` hides the rest of the filesystem and cannot be undone, so a call
  that failed partway left the federation worker running unable to see its own database
  (PR #510 OpenBSD CI, ADR-0162).
  Source: `src/platform/AGENTS.md`.

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

- **Sandbox profiles are named for the threat they contain, not for the kind of process
  that installs them. A new isolated child process gets its own profile unless its
  syscall needs are genuinely identical to an existing one.**
  Why: a profile named after a role (e.g. "worker") invites the next similar-sounding
  process to reuse it by analogy rather than by actually matching syscall needs. That is
  exactly how the thumbnail decoder — whose entire job is a pure function from bytes on
  stdin to bytes on stdout — ended up confined by the general server allowlist (sockets,
  `openat`, `execve`, `clone` all permitted) on Linux while the equivalent BSD sandboxes
  granted none of that. "It is also a worker" is not a reason to share `k_worker_*`.
  Source: [ADR-0053](adr/0053-the-thumbnail-decoder-gets-its-own-syscall-profile.md).

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

- **The federation worker's Landlock ruleset opt-out (`allow_without_landlock`) covers only
  "this kernel has no Landlock" — never "Landlock is present but broken".** A ruleset-create,
  add-rule, or `landlock_restrict_self` failure on a kernel that does support Landlock is
  always fatal, regardless of the opt-out.
  Why: an opt-out scoped to genuine kernel unavailability lets old-kernel deployments keep
  running without silently widening to cover a different failure mode (a broken ruleset,
  which would mean the sandbox never applied even though the operator believed only the
  "old kernel" case was being accepted). This mirrors the fail-closed seccomp policy in
  ADR-0041.
  Source: `src/platform/AGENTS.md`, `src/federation_worker/AGENTS.md`,
  [ADR-0062](adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md).

- **Landlock path rules for the federation worker must come from
  `build_worker_landlock_rules()`, derived from the worker's own config copy or a documented,
  best-effort fixed system path — never a hard-coded secret file path.**
  Why: the whole point of the ruleset is to name the paths the worker's own config exposes
  (the SQLite database directory) plus generic OS-integration paths, and to *never* name the
  master key file, either database URI file, or TLS private keys. A second, drifting
  hard-coded list is exactly the kind of duplication that silently diverges from the first.
  Source: `src/platform/AGENTS.md`,
  [ADR-0062](adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md).

- **No thread may exist before a process's Landlock ruleset and seccomp filter are installed;
  every seccomp filter is installed with `SECCOMP_FILTER_FLAG_TSYNC`.** The logger starts no
  thread until `SingleLog::start_writers()` is called (it writes synchronously until then),
  and an executable that hardens itself calls that only after hardening. `TSYNC` failure is
  fatal; never fall back to a per-thread install. The hardening self-check reads
  `/proc/self/task/<tid>/status` for every task, not `/proc/self/status`.
  Why: seccomp and Landlock attach to the calling thread only. Landlock has no thread-sync
  flag on older kernels, so ordering is the only thing that confines a thread against it.
  The logger's constructor once started two threads before the federation worker was
  sandboxed, and a compromised worker thread could aim a signal handler at one of them and
  run unconfined with `execve`, `open` and `connect` available.
  Source: `src/platform/AGENTS.md`, `src/observability/AGENTS.md`,
  [ADR-0082](adr/0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md).

- **Every executable's `main()` calls `platform::ignore_sigpipe()` first, before any thread
  starts, and exits non-zero if it fails.**
  Why: OpenSSL's socket BIO writes with plain `write()` and no `MSG_NOSIGNAL`. With the
  default SIGPIPE disposition, one TLS client that completes the handshake and resets the
  connection kills the whole server on the error response it writes back.
  Source: `src/platform/AGENTS.md`.

## Sync

- **Use `stream_token.hpp` — never parse or construct sync tokens manually.**
  Why: a sync token is opaque, client-supplied input on every subsequent request; a
  hand-rolled parser is much more likely to mishandle a malformed or adversarial token than
  the single, reviewed implementation, and inconsistent construction risks producing a token
  that either desyncs the client or leaks stream-position information it shouldn't.
  Source: `src/sync/AGENTS.md`.

- **Every client read path that returns room events or room state goes through
  `sync::HistoryVisibility` (events) and `sync::room_read_access_for` (state), and nothing
  else decides what a user may see.**
  Why: the spec judges visibility from the state at each event, and a path that re-derives a
  rule, or checks only "is a member", discloses history the room's owner restricted and lets a
  banned or departed user read on (audit CSAZ-2, CSAZ-3). The filter fails closed: no recorded
  state at an event means not visible, never a fallback to current state.
  Source: `src/sync/AGENTS.md`, `src/homeserver/AGENTS.md`.

- **A sliding-sync sort key is computed once per room before the sort, never inside the
  comparator, and the shape of a request's lists is capped (32 lists, 3 sort keys and 64
  `bump_event_types` per list; 400 `M_INVALID_PARAM` beyond).**
  Why: the sort runs while the runtime lock is held. Until 0.12.31 `by_recency` and `by_name`
  rescanned the event store on every comparison, with nothing bounding the lists, so one
  authenticated request could stall the whole server (CWE-407 Inefficient Algorithmic
  Complexity; security audit run-1, ADR-0172).
  Source: `src/sync/AGENTS.md`.

- **A client-named room list is capped and de-duplicated, and its rooms are classified
  through `sync::room_access_index`, built once per request, not `room_access_for` per room.**
  The receipts and typing extensions' `rooms` arrays share the `room_subscriptions` cap.
  Why: `room_access_for` scans every membership row in the store, and this runs under the
  runtime lock. Uncapped arrays let one request repeat that scan thousands of times (CWE-407;
  security audit run-1, ADR-0174).
  Source: `src/sync/AGENTS.md`.

## Push notifications

- **Glob matching for push rules is linear and never uses `std::regex`.** A pattern without
  wildcards is compared exactly; whole-value matching backtracks only to the last `*`;
  `content.body` matching is one pass over the body.
  Why: rules are evaluated for every local recipient of every event, under the runtime lock, on
  values the sender controls. The old matchers allocated per character and were quadratic in
  the body (CWE-407). `std::regex` backtracks and can take exponential time on patterns with
  several stars (CWE-1333). A randomised test pins the answers to the old implementation
  (ADR-0175).
  Source: `src/push/AGENTS.md`.
- **A user's push rules are bounded on write and re-validated on read.** At most
  `server.client_api.max_push_rules_per_user` user-defined rules, each with bounded ID, pattern and
  string lengths, condition and action counts and canonical size; the stored `m.push_rules` content
  is read through the same validator, and clients cannot set it through the account-data API (405).
  Why: a client's rules are evaluated under the runtime lock for every event it receives and every
  unread event a `/sync` counts, so their size is work the client would otherwise choose (CWE-400,
  ADR-0204).
  Source: `src/push/AGENTS.md`.
- **Unread counts, the push badge included, count only events the user may see, from their current
  join.** Every counted event passes `sync::HistoryVisibility::can_see` (`unread.visible()`,
  `classifier.visible()`); the join boundary alone does not exclude a backfilled pre-join event,
  which is ordered after the join. Why: the user's rules decide what counts, so a keyword rule
  counted over history they may not see would disclose whether it contains a word (CWE-203,
  ADR-0205).
  Source: `src/sync/AGENTS.md`.
- **Failed push notifications are retried only from the bounded queue, on the retry job.** Never
  sleep in a delivery task, never hold `runtime.mutex` across `notify`, and drop past the queue's
  bounds rather than block. Why: a failing gateway must not hold delivery slots, threads or
  unbounded memory (CWE-400, ADR-0206).
  Source: `src/push/AGENTS.md`.
- **An email pusher mails only an email 3PID the account holds, re-checked before every send.**
  Registration refuses any other `pushkey`; the email job deletes a pusher whose address has left
  the account and never mails a deactivated one. Why: otherwise any account can make the server
  send mail to an arbitrary address, an open relay with this server's reputation (CWE-441,
  ADR-0219).
  Source: `src/push/AGENTS.md`, `src/homeserver/AGENTS.md`.
- **An email address or server name that fails its check is refused, never escaped or repaired,
  before it reaches libcurl or a header.** Why: a CR, LF, NUL or `>` in an address is SMTP command
  or header injection, and a repaired address may belong to someone else (CWE-93, CWE-147).
  Source: `src/email/AGENTS.md`.
- **SMTP requires TLS (`CURLUSESSL_ALL`, verification on, TLS 1.2 minimum) except to a loopback IP
  literal with `require_tls=false`, and credentials are never sent without it.** Why:
  opportunistic STARTTLS can be stripped by anyone on the path, exposing the recipient and the
  password (CWE-319, ADR-0220).
  Source: `src/email/AGENTS.md`.
- **A notification email carries the unread count and server name only.** Why: room, sender and
  message content would be copied into mail infrastructure this server cannot delete from
  (CWE-359, ADR-0219).
  Source: `src/email/AGENTS.md`.

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
| `src/auth/AGENTS.md` | Secrets and logging; Cryptography; Authentication and authorization; Database |
| `src/events/AGENTS.md` | Cryptography; Authentication and authorization |
| `src/rooms/AGENTS.md` | Authentication and authorization |
| `src/federation/AGENTS.md` | Federation |
| `src/appservice/AGENTS.md` | Application Service API |
| `src/identity/AGENTS.md` | Identity Service client |
| `src/http/AGENTS.md` | HTTP and network boundary |
| `src/net/AGENTS.md` | Memory safety; HTTP and network boundary |
| `src/homeserver/AGENTS.md` | Authentication and authorization; HTTP and network boundary; Federation; Media; Sync |
| `src/media/AGENTS.md` | HTTP and network boundary; Media |
| `src/database/AGENTS.md` | Database |
| `migrations/AGENTS.md` | Database |
| `src/config/AGENTS.md` | Secrets and logging |
| `src/observability/AGENTS.md` | Secrets and logging |
| `src/platform/AGENTS.md` | Platform hardening |
| `src/federation_worker/AGENTS.md` | Platform hardening |
| `src/sync/AGENTS.md` | Sync |
| `src/push/AGENTS.md` | Push notifications |
| `src/email/AGENTS.md` | Push notifications |
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
