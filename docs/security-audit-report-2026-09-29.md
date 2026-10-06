# Merovingian Security Audit Report — 29 September 2026

**Scope:** Full security audit across all high-risk surfaces, audited sequentially one
area at a time.
**Baseline:** `6a04242` (0.12.13).
**Method:** For each area, one specialist auditor subagent, then one independent
adversarial verifier subagent whose job was to refute each finding, then orchestrator
spot-checks of every finding rated high or critical. Only findings that survived
verification are listed as findings; refuted ones are recorded at the end of each area.
**Authority:** Matrix spec v1.19 (`docs/matrix-v1.19-spec/`), project `AGENTS.md` files,
`docs/security-coding-rules.md`, `docs/threat-model.md`.
**Relationship to the earlier report:** `docs/security-audit-report-2026-09.md`
(33 findings, fixed in 0.12.9). Each area below re-checks the relevant earlier fixes for
regressions before looking for new defects.

This report records findings only. No production code was changed by this audit. Every
finding has a GIVEN/WHEN/THEN acceptance criterion; per `AGENTS.md`, the fix for each
must start with that test.

## Attacker models

| ID | Attacker |
|----|----------|
| A1 | Unauthenticated remote client |
| A2 | Authenticated local user (non-admin) |
| A3 | Malicious remote federating homeserver |
| A4 | Malicious or compromised application service |
| A5 | Compromised federation worker or thumbnail worker (escape towards the main process) |
| A6 | Local unprivileged OS user on the host |
| A7 | Malicious identity server, push gateway or remote media server answering our requests |

## Severity guide

- **Critical:** remote auth bypass, RCE, memory corruption reachable by A1/A3, signing-key leak.
- **High:** spec MUST violation or access-control bypass with real impact, cheap remote
  DoS, secret leakage, integrity defect reachable in production.
- **Medium:** real defect that is partly mitigated or needs unusual preconditions.
- **Low:** defence in depth.

## Areas

| # | Area | Status |
|---|------|--------|
| 1 | Authentication, sessions, application-service authentication | done: 2 high, 3 medium, 7 low |
| 2 | Client-Server authorisation and room access control | done: 4 high, 4 medium, 4 low |
| 3 | HTTP transport, TLS and request-level DoS | done: 3 high, 3 medium, 2 low |
| 4 | Federation inbound (X-Matrix, PDU ingestion, keys, backfill, membership) | done: 1 critical, 5 high, 3 medium, 3 low |
| 5 | Event engine (auth rules, state resolution, redaction, canonical JSON) | done: 5 high, 4 medium, 3 low |
| 6 | Outbound requests and SSRF (discovery, push, identity, appservice, remote media) | done: 1 high, 3 medium, 4 low |
| 7 | Cryptography, key management and worker IPC | done: 1 high, 1 medium, 4 low |
| 8 | Process isolation and platform hardening (workers, seccomp, sandboxes) | done: 1 high, 2 medium, 5 low |
| 9 | Media repository and thumbnailer | done: 5 medium, 3 low |
| 10 | Database, persistence and migrations | done: 1 high, 3 medium, 6 low |
| 11 | Configuration, observability, logging and packaging | done: 5 low |

## Remediation status

**Re-verified:** 5 October 2026 against `07317921` (0.12.18). Each finding was re-checked by
reading the current code and looking for a test that implements its acceptance criterion.
Nothing was built or run for that check. CHANGELOG, ADR and
`docs/todos/capability-gaps.md` claims were treated as claims, not evidence. The findings
below are otherwise unchanged.

**Update:** 6 October 2026 — every medium finding is now fixed on branch
`docs/audit-2026-09-29-status` (0.12.19). The first fixes for the ten that were still
open on 5 October were reviewed before being accepted, and six were wrong or incomplete.
Each correction has a regression test that failed against the first fix:

- **ISO-2:** the generated BPF entry for `tgkill` skipped one instruction too many, so
  every syscall not matched earlier in the worker allow list, including `kill`,
  `prlimit64` and `execve`, was allowed. The test that caught it had been changed to
  skip. Fixing that then showed that the worker's `start_runtime()` re-applied the main
  process's `setrlimit`, which the corrected filter denies, so a hardened worker would
  have crash-looped in production.
- **OUT-4:** the cache was consulted after the network fetch, so every request still
  went to the origin.
- **MED-5:** every port was stripped, so `example.org:8449` counted as this server.
- **MED-6:** the 10 MiB per-user default refused one upload at the 50 MiB upload limit
  and cut off each remote origin after 10 MiB.
- **DB-5:** media upload writes were still discarded.
- **CSAZ-10:** the caps on one-time keys, signatures and filters, and the signature
  index, were missing.

**Summary:** the critical finding, all 23 high findings and all 31 medium findings are
fixed. Of the 46 low findings, 3 are fixed, 2 are partly fixed and 41 are open.

### Fixed

- **Critical:** FED-1.
- **High:** AUTH-1, AUTH-11, CSAZ-1, CSAZ-2, CSAZ-3, CSAZ-4, HTTP-1, HTTP-2, HTTP-5, FED-2,
  FED-3, FED-4, FED-5, FED-7, EVT-1, EVT-2, EVT-3, EVT-4, EVT-6, OUT-7, CRY-1, ISO-1, DB-1.
- **Medium:** all 31 — AUTH-3, AUTH-4, AUTH-6, CSAZ-5, CSAZ-7, CSAZ-8, CSAZ-10, HTTP-3,
  HTTP-4, HTTP-8, FED-6, FED-8, FED-11, EVT-5, EVT-7, EVT-8, EVT-9, OUT-1, OUT-2, OUT-4,
  CRY-2, ISO-2, ISO-3, MED-1, MED-2, MED-3, MED-5, MED-6, DB-2, DB-3, DB-5.
- **Low:** AUTH-9, HTTP-6, OUT-5. AUTH-9: the control-character escaping is done; the
  field-length cap from its fix is not. OUT-5: `CURLOPT_PROXY` is set to `""` on the
  only curl handle, but there is no regression test with `https_proxy` set.

Residual notes on fixed findings:

- **EVT-1:** rule 4.2 (v10 numbering) applies to every `m.room.member` event that carries
  `join_authorised_via_users_server`. `src/events/authorization.cpp` checks it only in
  the restricted branch, after the "already invited or joined" allow. Federation
  ingestion verifies the signature for every PDU carrying the key
  (`src/federation/inbound_request.cpp`), so remote events are covered, but the auth rule
  is not ordered as the spec orders it and the cryptographic path has no test.
- **AUTH-1:** fixed by rate-capping unauthenticated audit rows. `login.rejected` is not
  gated and relies on the per-IP limit.
- **AUTH-4:** Argon2id hashing in ordinary `/register` (`make_user`) and password
  verification in user-interactive auth still run under the runtime mutex with no
  admission limit.
- **ISO-2:** the worker still runs under main's uid, which the audit preferred; the
  seccomp argument checks and, on Landlock ABI 6 kernels, signal scoping are what stop it
  signalling main.
- **MED-5:** discovery results that resolve to this server are not rejected. A self-fetch
  cannot loop (the federation media endpoint serves local media only, and the legacy
  fallback carries `allow_remote=false`), but it costs one outbound request.
- **DB-1, DB-2:** the PostgreSQL integration tests skip unless
  `MEROVINGIAN_TEST_POSTGRESQL_URI` is set.

### Fixed — medium, 6 October 2026

| ID | Resolution |
|----|------------|
| AUTH-3 | Application-service `sender_localpart` users are created at startup from the loaded registry (the loop read the runtime registry before it was populated) and ordinary `/register` rejects them with `M_EXCLUSIVE`. |
| CRY-2 | The reader-side dispatch queue is capped by frames (1024) and bytes (128 MiB); a worker past either has its channel marked unhealthy and is replaced. IPC sockets have a 30 s send timeout. ADR-0111. |
| CSAZ-10 | To-device queues are capped per device by count and age (migration 019, ADR-0117); rows written before migration 019 are no longer dropped on the next enqueue. One-time keys (1000 per device), key signatures (10000 per user) and filters (1000 per user) are capped, refusing with `400 M_TOO_LARGE`; identical filters are deduplicated; one fallback key per algorithm per device, as the spec requires; key signatures are indexed by target. ADR-0118. |
| DB-2 | The SQLite room snapshot loads event relations with a room-scoped JOIN instead of one parameter per event. |
| DB-5 | Token revocations (logout, logout-all, refresh rotation and reuse, device deletion, password change) are checked against the store and answer 500 when not durable (ADR-0116). A media upload's record and blob commit in one transaction; on failure the upload answers 500 and is rolled back in memory. |
| FED-6 | `handle_make_membership` rejects a `{userId}` that is not on the requesting server. |
| ISO-2 | The worker filter denies `kill`, `tkill` and `setrlimit`, allows `tgkill` only on the worker's own thread group and `prlimit64` only to read its own limits; Landlock ABI 6 kernels also scope signals. The worker's `start_runtime()` no longer re-applies the main-process profile. Tested by installing the real filter in a forked child (`[iso2]`) and by starting a real hardened worker (`[federation-worker][seccomp]`). ADR-0112. |
| MED-5 | Media `serverName` comparisons lowercase the name and drop only a trailing `:8448`. ADR-0115. |
| MED-6 | Quota defaults are `2GiB` total, `256MiB` per user and `100000` records (all media is held in memory, so the total is a memory budget); remote media is exempt from the per-user quota only. Blob bytes are held once in memory. ADR-0113. |
| OUT-4 | Remote media admitted within the TTL is served from the stored copy before any outbound slot, discovery or request; expired and stale entries are erased and a zero entry cap disables the cache. ADR-0114. |

### Outstanding — medium

None.

### Outstanding — low

| ID | State | What remains |
|----|-------|--------------|
| EVT-12 | Partial | (b) the creator-without-member-event fallback is removed. (a) there is still no v3–v5 `m.room.aliases` rule, and (c) rejected events are still accepted as auth events. |
| OUT-3 | Partial | Pushers per delivery are capped (`push.max_pushers_per_delivery`). There is still no per-user in-flight cap, no stalled-gateway circuit breaker and no cap on pusher registrations. |

Open, with no code, test or documentation change found: AUTH-2, AUTH-5, AUTH-7, AUTH-8,
AUTH-10, AUTH-12, CSAZ-6, CSAZ-9, CSAZ-11, CSAZ-12 (all four endpoints), HTTP-7, FED-9,
FED-10, FED-12, EVT-10, EVT-11, OUT-6, OUT-8, CRY-3, CRY-4, CRY-5, CRY-6, ISO-4, ISO-5,
ISO-6, ISO-7, ISO-8, MED-4, MED-7, MED-8, DB-4, DB-6, DB-7, DB-8, DB-9, DB-10, OPS-2,
OPS-3, OPS-4, OPS-5, OPS-6.

The documentation corrections listed under "Documentation found to be wrong about the
code" for AUTH-2, CRY-6, ISO-4, OPS-2, OUT-8 (`deny_ip_ranges`) and CSAZ-11 have not
been made.

---

## Area 1 — Authentication, sessions, application-service authentication

**Result:** 12 findings confirmed (2 high, 3 medium, 7 low); none refuted. Two of the 12
came from the verifier. Every prior-audit fix in this area still holds: H-01, H-02, M-01,
M-02, M-04, M-05, L-01, L-02, L-03, M-11, L-10.

**What is sound:** access tokens are 32 random bytes, stored as keyed BLAKE2b hashes,
compared in constant time and revoked one way. The masquerade-token spoofing guard holds.

### AUTH-1 — Unauthenticated requests write unbounded, synchronous audit rows under the global lock

- **Severity:** high · **Attacker:** A1 · **Verdict:** confirmed (orchestrator re-checked)
- **Location:** `src/homeserver/client_server.cpp:2795-2830`,
  `src/homeserver/auth_service.cpp:1443-1465`, `src/homeserver/local_services.cpp:106-121`,
  `src/database/persistent_store.cpp:2722-2737`
- **Rule:** `docs/security-coding-rules.md` (bounded resources; no heavy work under the
  global lock).
- **Path:**
  1. Any request with `Authorization: Bearer <junk>` reaches the rate-limit check, which
     calls `authenticated_user` to build the per-user key while the runtime mutex is held
     (`client_server.cpp:8813`).
  2. An unknown token calls `log_diagnostic_audit`, then `append_local_audit`. That pushes
     to `LocalDatabase::audit_events` (an uncapped `std::vector`) and runs
     `database::append_audit_event`, which commits synchronously (on SQLite, one
     connection and one commit per row) and pushes to `PersistentStore::audit_log`, also
     uncapped.
  3. A request the rate limiter denies writes the `rate_limit.exceeded` audit row as
     well, so denial adds work instead of shedding it.
  4. Failed `/login` also records the raw client `user` and `device_id` strings as actor
     and target. `parse_login_body` does not bound their length (up to the 64 KiB body
     cap). That path is throttled per IP at 20/min.
- **Why reordering alone does not fix it:** a denied request still writes an audit row.
  The root cause is that A1 can trigger audit appends that are unbounded, synchronous and
  made under the lock.
- **Impact:** permanent memory and table growth, plus a DB commit under the global lock
  on every junk request. `max_connections_per_ip` (64) limits concurrency, not rate.
- **Fix:**
  - Bound the in-memory audit containers (the durable copy lives in the DB).
  - Record per-request unauthenticated rejections as counters, or as sampled or
    rate-capped audit rows written outside the runtime mutex.
  - Truncate attacker-controlled audit fields to a fixed length.
- **Test:** GIVEN a runtime with an audit sink WHEN 10 000 requests carry an unknown bearer
  token THEN in-memory audit storage stays within a documented cap AND fewer than 10 000
  synchronous audit commits occur AND a `/login` with a 60 KiB `user` records an actor of
  at most 255 bytes.

### AUTH-11 — Every committed statement, parameters included, is kept in memory for the life of the process

- **Severity:** high · **Attacker:** A2 (any write), and A1 through AUTH-1 · **Verdict:**
  found by the verifier, confirmed by the orchestrator
- **Location:** `src/database/persistent_store.cpp:549-552`;
  `include/merovingian/database/persistent_store.hpp:942-948`
- **Path:**
  1. `commit_persistent_transaction` appends every `PreparedStatement` it persists,
     including all bound parameters, to `PersistentStore::prepared_statements`.
  2. The only reader is `sensitive_values_are_redacted`
     (`persistent_store.cpp:3706-3707`), a check used by tests. Nothing trims the vector.
- **Impact:**
  - Memory grows with every database write the server ever makes: every event, receipt,
    audit row and token.
  - Password hashes and token hashes stay resident in heap memory indefinitely.
  - Every write-path finding in this report (AUTH-1 included) is amplified by it.
- **Fix:** do not keep committed statements in production. If a test needs to inspect
  them, give the test an explicit, bounded capture hook.
- **Test:** GIVEN a store with no capture hook WHEN 10 000 transactions commit THEN the
  retained statement count is zero (or bounded by a fixed cap).
- **Note:** Area 10 (database) re-examines this alongside the other persistence paths.

### AUTH-4 — Argon2id verification for unauthenticated requests runs under the global runtime mutex

- **Severity:** medium · **Attacker:** A1 · **Verdict:** confirmed
- **Location:**
  - `src/homeserver/auth_service.cpp:1029-1031` (login, including the dummy hash for
    unknown users)
  - `src/homeserver/auth_service.cpp:948-951` (registration token)
  - `src/homeserver/client_server.cpp:9132-9146` (registration-token validity endpoint)
  - `src/http/rate_limit.cpp:60-64` (rate-limit tiers)
- **Path:**
  1. No login or register path releases the runtime lock (`RuntimeLockRelease`) around
     `crypto_pwhash_str_verify` (`OPSLIMIT_INTERACTIVE`/`MEMLIMIT_INTERACTIVE`).
  2. Each unauthenticated verification therefore stalls every client and federation
     request.
  3. `rate_limit_tier_for` matches only `/_matrix/client/v3/register`.
     `/_matrix/client/v1/register/m.login.registration_token/validity` therefore falls into
     the generic tier (90/min per IP instead of 20/min).
  4. That handler runs an Argon2 verify without checking whether registration is enabled.
- **Spec:** that endpoint is marked "Rate-limited: Yes" ("Servers should be sure to rate
  limit this endpoint"). A limit exists, so the tier choice is not a spec violation.
- **Impact:** a modest set of source addresses can serialise the whole server behind
  password hashing.
- **Fix:**
  - Snapshot the stored hash, release the runtime lock, verify, then re-acquire.
  - Bound concurrent hash work with a semaphore that sheds load with 429.
  - Put `/v1/register/*` in the `auth_sensitive` tier.
  - Refuse the validity endpoint with 403 when registration is disabled.
- **Test:** GIVEN 64 concurrent failed logins from distinct addresses WHEN `/versions` is
  requested THEN it completes within a small bound; AND the validity path is classified
  `auth_sensitive`.

### AUTH-3 — An application service's `sender_localpart` user is neither reserved nor created

- **Severity:** medium · **Attacker:** A1 or A2 (only where registration is open or
  token-gated) · **Verdict:** confirmed · **Status:** fixed in 0.12.19
- **Location:**
  - `src/homeserver/client_server.cpp:9480-9487` (ordinary registration checks only
    `namespaces.users`)
  - `src/homeserver/client_server.cpp:8712-8716` (the sender is the default masquerade
    identity)
  - `src/appservice/registration.cpp:544-546` (comment wrongly says "created at startup")
- **Path:**
  1. Ordinary `/register` rejects a name only if it matches another service's exclusive
     `users` regex.
  2. The spec defines `users` as "in addition to its `sender_localpart`", so a sender
     localpart outside that regex is accepted.
  3. The registrant then owns the account the bridge acts as by default: its password,
     its `/sync` and its room memberships.
- **Precondition:** the sender localpart falls outside the service's own exclusive regex.
  The spec's example (`_irc_bot` vs `@_irc_.*`) is protected.
- **Impact:** takeover of the bridge bot identity and read access to its rooms.
- **Fix:**
  - At startup, create or verify every registration's sender as a passwordless
    application-service user.
  - Reject ordinary `/register` and `/register/available` for any sender user ID with
    `M_EXCLUSIVE`.
  - Correct the code comment.
- **Test:** GIVEN an appservice whose `sender_localpart` is `bridgebot` and lies outside
  its namespace WHEN an ordinary user registers `bridgebot` THEN 400 `M_EXCLUSIVE` AND
  after startup `@bridgebot:<server>` exists with no password.

### AUTH-6 — Application-service user namespaces have no local-server check

- **Severity:** medium · **Attacker:** A4 · **Verdict:** confirmed; the auditor's spec
  citation was out of context
- **Location:**
  - `src/appservice/registration.cpp:107-120` and `:150-158`
  - `src/homeserver/client_server.cpp:8721`
  - `src/homeserver/auth_service.cpp:1427`, `:1519`
- **Path:**
  1. `appservice_owns_user` regex-matches the whole user ID.
  2. The spec's own example regex (`@_irc_bridge_.*`) has no domain anchor, so
     `?user_id=@_irc_bridge_x:remote.org` is accepted as the masqueraded identity.
  3. `registration_yaml.cpp` validates regex syntax only.
- **Spec:** identity assertion requires the user to be "covered by one of the application
  service's `user` namespaces". Namespaces concern local users ("application services can
  only register interest in *local* users").
- **Impact:** a compromised appservice can act locally as a foreign user, and those events
  are signed by this server.
- **Fix:** require the local server name in `appservice_owns_user` and every masquerade,
  login and register path, before the regex test.
- **Test:** GIVEN an appservice with regex `@_x_.*` WHEN it asserts
  `?user_id=@_x_a:other.org` THEN 403 `M_FORBIDDEN`.

### AUTH-2 — Anyone can hold any account in login lockout, and the documentation says otherwise

- **Severity:** low (a documented trade-off; one doc claim is false) · **Attacker:** A1 ·
  **Verdict:** adjusted from medium
- **Location:** `src/homeserver/auth_service.cpp:161-235`, `:1009-1044`, `:1859-1876`;
  `docs/auth-identity.md:509-541`
- **Detail:**
  - The throttle is keyed on the claimed user ID only.
  - Five failures refuse all logins for 15 minutes, correct passwords included, at a cost
    of 5 requests per 15 minutes per victim.
  - User-interactive auth (UIA) password checks share the counter, so the victim also
    cannot change their password, deactivate, or delete devices.
  - `docs/auth-identity.md` says the lockout is bounded "by a real login clearing it
    immediately", which cannot happen while locked. The same document later says a
    correct password during lockout is still refused, so it contradicts itself.
- **Fix:**
  - Correct the document.
  - Key failures on (account, source) with a higher per-account ceiling.
  - Do not let unauthenticated failures block UIA from an already-authenticated device.
- **Test:** GIVEN 5 failed logins for U from address A WHEN U's authenticated device
  performs a UIA password check THEN it is not refused with 429.

### AUTH-5 — 3PID ownership is never validated

- **Severity:** low · **Attacker:** A2 · **Verdict:** adjusted from medium (SHOULD-level;
  3PIDs are not used for login or password reset)
- **Location:** `src/homeserver/client_server.cpp:1900-1902`, `:9221`, `:10480-10611`
- **Detail:**
  - `requestToken` sessions are created with `validated_at_ms = now` and nothing is sent.
  - `/account/3pid/add` and `/bind` accept any session whose `sid` and `client_secret`
    match.
  - A user can therefore bind someone else's email address, and the real owner is then
    refused with `M_THREEPID_IN_USE`.
  - Spec: "The homeserver should validate the email itself, either by sending a
    validation email itself or by using a service it has control over."
  - `docs/auth-identity.md:37` ("local validation sessions") overstates what exists.
- **Fix:** create sessions unvalidated. Refuse `/add` and `/bind` with
  `M_SESSION_NOT_VALIDATED` until an out-of-band proof arrives.
- **Test:** GIVEN a fresh `requestToken` session WHEN `/account/3pid/add` is called THEN
  400 `M_SESSION_NOT_VALIDATED` and nothing is bound.

### AUTH-7 — Appservice register, login and masquerade ignore other services' exclusive namespaces

- **Severity:** low · **Attacker:** A4 · **Verdict:** confirmed
- **Location:** `src/homeserver/client_server.cpp:9387`, `:9650`, `:8721`;
  `src/appservice/registration.cpp:483-521`
- **Detail:**
  - None of these paths calls `user_namespace_exclusively_owned_by_other(user,
    registration.id)`.
  - Overlap detection catches only identical regex strings.
  - Spec: "An exclusive namespace prevents humans and other application services from
    creating/deleting entities in that namespace."
- **Fix:** apply the exclusivity check on appservice register and login.
- **Test:** GIVEN service A (`@.*`, non-exclusive) and service B (`@_b_.*`, exclusive)
  WHEN A registers `_b_x` THEN 403 `M_EXCLUSIVE`.

### AUTH-8 — Identity assertion is honoured on 3PID management endpoints

- **Severity:** low · **Attacker:** A4 · **Verdict:** adjusted (narrower scope)
- **Location:** `src/homeserver/client_server.cpp:10524`, `:10612`, `:10699`, `:10796`
- **Detail:**
  - Spec: identity assertion "applies to all aspects of the Client-Server API, except for
    Account Management".
  - Password change, deactivate and `/3pid/add` are protected by password UIA.
  - `/3pid/bind`, `/3pid/delete`, `/3pid/unbind` and the deprecated `POST /account/3pid`
    are not, and accept a masqueraded identity.
- **Fix:** refuse masquerade tokens on `/account/*` except `whoami`.
- **Test:** GIVEN a masqueraded request WHEN `POST /account/3pid/delete` THEN 403.

### AUTH-9 — Control characters in login fields reach text logs unescaped

- **Severity:** low · **Attacker:** A1 · **Verdict:** confirmed
- **Location:** `include/merovingian/observability/logger.hpp:368-374`, `:703-712`;
  `src/homeserver/auth_service.cpp:1000-1004`, `:1036-1048`
- **Detail:**
  - A JSON `\n` in `identifier.user` or `device_id` forges extra log lines.
  - Redaction works by key only; no control-character escaping exists in
    `src/observability/`.
  - Audit database rows are bound parameters and are not affected.
- **Fix:** escape control characters and cap the length of every structured log field
  value.
- **Test:** GIVEN a login whose `user` contains `\n` WHEN diagnostics are captured THEN
  each event is one physical line.

### AUTH-10 — The failed-login map is unbounded and scanned in full on every failure

- **Severity:** low · **Attacker:** A1 · **Verdict:** confirmed
- **Location:** `src/homeserver/auth_service.cpp:185-195`, `:219-233`;
  `include/merovingian/homeserver/runtime.hpp:349`
- **Fix:** cap the map, hash or truncate keys, and expire entries from a time-ordered
  queue.
- **Test:** GIVEN 100 000 failed logins for distinct IDs THEN the map never exceeds its
  cap.

### AUTH-12 — An appservice can act as a deactivated or non-existent user

- **Severity:** low · **Attacker:** A4 · **Verdict:** found by the verifier
- **Location:** `src/homeserver/auth_service.cpp:1426-1436`, `:1879-1897`
- **Detail:**
  - The masquerade branch of `authenticated_user` does not look the user up.
  - `account_state_for_user` gates only locked and suspended accounts.
- **Fix:** refuse masquerade as a deactivated user. Decide explicitly whether
  non-existent users in a namespace may be asserted; the spec allows implicit
  registration only through `/register`.
- **Test:** GIVEN a deactivated user in an appservice namespace WHEN the service asserts
  that user THEN 403.

### Area 1 — correctness notes (not security findings)

- `upgrade_v3_access_token_to_v4` (`auth_service.cpp:504-548`) passes a `string_view` into
  the string it then overwrites. The persisted upgrade therefore never happens. The path
  is legacy-only and has no security impact. Copy the value first.
- `server_name_from_user_id` uses `rfind(':')`. On a `host:port` server name, lock and
  suspend fail closed with a spurious `M_INVALID_PARAM` (`client_server.cpp:1015`, `:1285`;
  `local_http_router.cpp:544`).
- `change_local_user_password` discards revocation persistence failures with
  `std::ignore` (`auth_service.cpp:1773`, `:1826-1836`). After a database fault, revoked
  sessions come back on restart.
- `register_local_user` passes a hard-coded `"127.0.0.1"` to the registration policy
  (`auth_service.cpp:941`). No policy uses the value, so it only misleads diagnostics.

### Area 1 — coverage gaps

- Not examined: `src/appservice/registration_yaml.cpp`, `appservice_client.cpp`,
  `src/identity/`, token hydration at startup, and `masquerade_token.cpp` delimiter
  handling.
- `src/auth/key_api.cpp` and the E2EE key handlers are left to Area 2.

---

## Area 2 — Client-Server authorisation and room access control

**Result:** 12 findings confirmed: 4 high, 4 medium, 4 low. One sub-claim was refuted
(see the end of this area). The earlier report had no findings in this area.

**What holds:**
- Admin gates.
- Per-user resources:
  - filters, account data, tags, pushers and key backup;
  - OpenID tokens;
  - `PUT` typing and presence for the caller only;
  - `/keys/upload` user and device binding;
  - cross-signing uploads behind UIA.
- Rejected and soft-failed events are withheld (ADR-0064 B2) on `/messages`, `/context`,
  `/event`, `/sync`, search and sliding sync.

### CSAZ-1 — Sliding sync serves any room to any user who names it

- **Severity:** high
- **Attacker:** A2. Most realistically a former, kicked or banned member who still knows
  the room ID.
- **Verdict:** confirmed; re-checked by the orchestrator.
- **Location:**
  - `src/homeserver/client_server.cpp:4598-4605` (subscription IDs added to the
    response set)
  - `src/sync/sliding_sync_parser.cpp:277-281`, `:467-480`
  - `src/sync/sliding_sync_room_builder.cpp:600-805`
  - `src/sync/sliding_sync_extensions.cpp:213-290`
- **Spec:** "In all cases except `world_readable`, a user needs to join a room to view
  events in that room."
- **Path:**
  1. `POST /_matrix/client/v4/sync` carries
     `{"room_subscriptions":{"!victim:srv":{"required_state":[["*","*"]],"timeline_limit":1000}}}`.
     There is no feature flag.
  2. Every subscription key is appended to `response_room_ids` without a membership
     check.
  3. `build_room_response` returns the name, heroes, member counts, all state that
     matches the wildcard, and up to `timeline_limit` events (the limit is unclamped).
  4. The `receipts` and `typing` extensions return whatever rooms the client names in
     `extensions.*.rooms`. That includes other users' `m.read.private` receipts (see
     CSAZ-4).
  5. The list path is limited to joined rooms (`sliding_sync_room_list.cpp:447-459`), so
     the missing check here is an omission, not a design choice.
- **Impact:**
  - The room ID is the only secret. Rooms on room versions below 12 get sequential IDs
    (`!room<N>:server`, `room_service.cpp:2547-2548`).
  - Each subscription scans `store.events` in full, so a single request is also a CPU
    amplifier.
- **Existing test:** `tests/integration/test_sliding_sync_flow.cpp:1745-1800` subscribes
  an invited, not-joined user and receives the room. It asserts ignore-list behaviour,
  not refusal.
- **Fix:**
  - Drop subscription and extension rooms the user has not joined; invitees get
    stripped state only.
  - Clamp `timeline_limit`, the number of subscriptions and the number of
    `required_state` entries.
- **Test:** GIVEN alice in a private room and mallory in no room WHEN mallory subscribes
  to that room with `required_state [["*","*"]]` and names it in the receipts and typing
  extensions THEN the response has no entry for it AND both extensions are empty.

### CSAZ-2 — `initialSync` and `/members` admit any membership row, including after leave or ban

- **Severity:** high
- **Attacker:** A2 — a knocker, invitee, or banned or departed user.
- **Verdict:** adjusted; the `/state/{type}/{key}` sub-claim was refuted. Re-checked by the
  orchestrator.
- **Location:**
  - `src/homeserver/client_server.cpp:12938-12963` (initialSync gate)
  - `:7428-7514` (initialSync response)
  - `:12691-12769` (`/members`)
- **Spec:**
  - "After a user has left a room, they may see any events which they were allowed to see
    before they left the room, but no events received after they left."
  - `/members` 200: "If you have left the room then this will be the members of the room
    when you left."
- **Path:**
  1. The initialSync gate is `is_or_was_member = membership.has_value()`, so invite,
     knock, ban and leave rows all pass.
  2. `room_initial_sync_json` then returns the latest 100 events and the full current
     state, with no leave cut-off.
  3. `/members` accepts any row, always returns the current roster (ban reasons
     included), and ignores `at`.
  4. On a room with a `knock` join rule, anyone can create such a row by knocking.
- **Impact:**
  - Banned and departed users keep reading new messages, state and the roster
    indefinitely.
  - Knockers read rooms they have not been admitted to.
- **Fix:**
  - Add one `may_read_room(user, room, at)` predicate: joined users see the current
    state; users who left after joining see state as of their leave event; invite, knock
    and never-joined leave see stripped state only.
  - Apply it to initialSync, `/members`, `/state` and `/state/{type}/{key}`.
  - Honour `at` on `/members`.
- **Test:**
  - GIVEN a knock room with history WHEN mallory knocks and calls initialSync and
    `/members` THEN both return 403.
  - GIVEN bob was banned WHEN a new message is sent and bob calls initialSync THEN the
    new message is absent.

### CSAZ-3 — `m.room.history_visibility` is not enforced on any client read path

- **Severity:** high · **Attacker:** A2 · **Verdict:** confirmed (orchestrator grep: the
  setting is read only for `/publicRooms`, the initialSync peek and the space hierarchy)
- **Location:**
  - `src/homeserver/client_server.cpp:6514-6616` (`/messages`), `:6676-6796` (`/context`),
    `:12326-12360` (`/event`), `:3798-3903` (`/sync` timeline), `:7171+` (search)
  - `src/homeserver/room_service.cpp:6414-6612` (`/relations`, `/threads`)
  - `src/sync/sliding_sync_room_builder.cpp:674-721`
- **Spec:** "The rules governing whether a user is allowed to see an event depend on the
  state of the room *at that event*." The spec then gives five allow and deny rules for
  `world_readable`, `join`, `shared`, `invited`, and otherwise.
- **Impact:**
  - In a room set to `joined` or `invited`, a newcomer reads the entire prior history.
    The owner's privacy setting has no effect.
  - The default (`shared`) is unaffected.
  - No document lists this as a gap, and no test asserts enforcement.
- **Fix:**
  - Add a per-request `event_visible_to(user, event)` that implements the five rules
    against the state at each event, using the existing state groups.
  - Apply it on every read path, including the state returned by `/context` and the
    `/sync` join snapshot.
- **Test:** GIVEN a room with visibility `joined`, message M1, then bob joins WHEN bob
  calls `/messages`, `/context` on M1, `/event` on M1, `/search`, `/relations`, `/sync` and
  sliding sync THEN M1 is absent or refused. WHEN the visibility is `shared` THEN M1 is
  present.

### CSAZ-4 — `m.read.private` and `m.fully_read` receipts are sent to every room member

- **Severity:** high (spec MUST) · **Attacker:** A2 · **Verdict:** confirmed; re-checked by
  the orchestrator
- **Location:** `src/homeserver/client_server.cpp:3473-3517`, `:13210-13369`;
  `src/sync/sliding_sync_extensions.cpp:225-290`
- **Spec:**
  - "Servers MUST NOT send the `m.read.private` receipt to any other user than the one
    which originally sent it."
  - "`m.fully_read` does not appear under `m.receipt`".
- **Path:** the `/sync` and sliding-sync receipt builders index every stored receipt of
  the room by type and user. They filter only on the stream position and the ignore
  list.
- **Existing test:** `tests/conformance/test_client_server_conformance.cpp:10164-10225`
  has a comment claiming "not visible to other members" but tests only the owner's
  notification count.
- **Fix:**
  - One shared helper: send `m.read` to other users, `m.read.private` to its owner only,
    and never `m.fully_read` in `m.receipt`.
  - Deliver `m.fully_read` to its owner as room account data.
- **Test:** GIVEN alice and bob in a room WHEN alice sends an `m.read.private` receipt
  THEN bob's `/sync` and sliding sync contain no alice receipt, while alice's own
  `/sync` does.

### CSAZ-5 — `/publicRooms` ignores directory visibility

- **Severity:** medium · **Attacker:** A1 · **Verdict:** adjusted from high
- **Location:**
  - `src/homeserver/client_server.cpp:3081-3160`, `:10277-10304`, `:11793-11805`
  - `include/merovingian/homeserver/runtime.hpp:126`
- **Spec:**
  - "`private`: The room will be hidden from the published room directory."
  - "a visibility setting of `public` should not be confused with a `public` join
    rule".
- **Detail:**
  - The listing selects rooms by `join_rule == public`, and `directory_public` is never
    consulted.
  - `createRoom`'s `visibility` only picks the preset.
  - The flag is in memory only and is lost on restart.
  - `POST /publicRooms` is also routed before authentication, although the spec says it
    "Requires authentication: Yes". Unauthenticated `GET` already returns the same data,
    so this is a deviation only.
- **Impact:** rooms the owner chose to keep out of the directory are listed with name,
  topic, alias and member count. The auditor rated this high; it is medium because it
  exposes metadata only, and these rooms are already joinable by anyone who knows the ID.
- **Fix:**
  - Persist a directory flag, set it from `createRoom` `visibility`, and list only
    flagged rooms. This needs a numbered migration, which `migrations/AGENTS.md`
    requires to be approved first.
  - Require authentication on `POST`.
- **Test:** GIVEN a `public_chat` room created with the default visibility WHEN
  `GET /publicRooms` is called THEN the room is absent AND an unauthenticated `POST`
  returns 401.

### CSAZ-7 — Invite and knock "stripped state" is the whole current state, as full events

- **Severity:** medium · **Attacker:** A2 · **Verdict:** confirmed
- **Location:** `src/homeserver/client_server.cpp:1073-1095`, `:4016-4026`;
  `src/homeserver/room_service.cpp:846-867`
- **Spec:** "Stripped state events can only have the `sender`, `type`, `state_key` and
  `content` properties present."
- **Impact:** a knocker receives every member event, the power levels, the ACLs and more,
  each with event IDs, hashes and signatures.
- **Fix:** build the stripped set: create, name, avatar, topic, join rules, canonical
  alias, encryption, and the user's own member event, each reduced to the four permitted
  keys.
- **Test:** GIVEN a knock room with 3 members WHEN mallory knocks and syncs THEN
  `knock_state` has no foreign `m.room.member` and no `m.room.power_levels`, and no event
  carries `event_id` or `hashes`.

### CSAZ-8 — `/sync` sends every known user's presence to every user

- **Severity:** medium · **Attacker:** A2 · **Verdict:** confirmed
- **Location:** `src/homeserver/client_server.cpp:3599-3640`, `:13548-13588`
- **Spec:** "Presence information is published to all users who share a room with the
  target user."
- **Detail:**
  - Only the caller's own presence is excluded; there is no shared-room filter.
  - `PUT` presence accepts any `presence` string and a `status_msg` of any length up to
    the body cap.
- **Fix:**
  - Send presence only for users who share a joined room with the viewer.
  - Validate `presence` against `online`, `unavailable` and `offline`.
  - Cap `status_msg`.
- **Test:** GIVEN alice and bob with no common room WHEN alice sets a status message THEN
  bob's `/sync` has no presence from alice; AND `presence:"x"` returns 400.

### CSAZ-10 — To-device messages to non-existent recipients are queued forever

- **Severity:** medium · **Attacker:** A2 · **Verdict:** confirmed for to-device; the other
  sub-claims are only partly verified · **Status:** fixed in 0.12.19
- **Location:** `src/homeserver/client_server.cpp:5972-6083`;
  `src/database/persistent_store.cpp:2853-2934`; `src/federation/key_signatures.cpp:90-135`
- **Detail:**
  - No check that the target user or device exists.
  - The drain deletes only rows that a real device has acknowledged, so rows for
    wildcard targets or non-existent devices are never removed.
  - One-time keys and key-signature uploads have no per-user cap, and each
    `/keys/query` scans every signature upload under the global lock.
- **Fix:**
  - Reject or drop messages for unknown local users and devices.
  - Cap the per-recipient queue and add a TTL.
  - Cap one-time keys, signatures and filters per user.
  - Index signatures by target.
- **Test:** GIVEN a user WHEN they send 10 000 to-device messages to a non-existent device
  THEN the store stays bounded.

### CSAZ-6 — Membership changes sent through `PUT /state/m.room.member` skip the membership projection

- **Severity:** low · **Attacker:** A2 (the effect is a failed moderator action) ·
  **Verdict:** adjusted from medium
- **Location:** `src/homeserver/client_server.cpp:12246-12280`;
  `src/homeserver/room_service.cpp:6041-6207`
- **Detail:**
  - A ban or kick sent through the state API changes room state.
  - It does not update `memberships` or `LocalRoom.members`, so the banned user keeps
    read access through every gate keyed on those.
  - Federated membership events are projected correctly.
- **Fix:** project membership at one choke point for every accepted `m.room.member`
  event, and make read gates consult resolved state.
- **Test:** GIVEN bob joined WHEN a moderator bans him through
  `PUT /state/m.room.member/@bob` THEN bob's next `/messages` returns 403.

### CSAZ-9 — Locally created events are not checked against the spec size limits

- **Severity:** low · **Attacker:** A2 · **Verdict:** adjusted from medium
- **Location:** `src/homeserver/room_service.cpp:1303-1518`;
  `include/merovingian/events/limits.hpp:96`, `:105`
- **Spec:** "The complete event MUST NOT be larger than 65536 bytes"; `type` and
  `state_key` "MUST NOT exceed 255 bytes".
- **Detail:** only inbound federation enforces the limits. A body near the 64 KiB cap,
  or a long `type` or `state_key` in the URL, produces a PDU that other servers reject.
- **Fix:** enforce the limits on the composed, signed event in `compose_signed_event`
  and return `M_TOO_LARGE`.
- **Test:** GIVEN a member WHEN the composed event is 65 537 bytes, or its `state_key`
  is 256 bytes THEN 400 `M_TOO_LARGE` and nothing is stored.

### CSAZ-11 — Redactions are accepted and relayed but never applied

- **Severity:** low · **Attacker:** A2 or A3 · **Verdict:** adjusted
- **Location:** `src/events/authorization.cpp:1505-1511`;
  `docs/todos/capability-gaps.md:95`
- **Spec:** `rooms/v12.md` "Handling redactions"; client-server "Redactions": "This
  stripped down event is thereafter returned anytime a client or remote server requests
  it."
- **Detail:**
  - `PUT /redact` is documented as not started.
  - What is not documented is that `m.room.redaction` events arriving through `/send` or
    federation are relayed without a validity check and never applied, so the original
    content is still served.
- **Fix:** apply valid redactions (the `redacted_because` field), relay only valid ones,
  and correct the capability-gaps row.
- **Test:** GIVEN alice's message M WHEN alice redacts it THEN `/event` on M returns the
  redacted form.

### CSAZ-12 — Missing membership or power checks on `/report`, `/upgrade`, directory visibility and aliases

- **Severity:** low · **Attacker:** A2 · **Verdict:** confirmed
- **Location:** `src/homeserver/client_server.cpp:8269-8286`, `:13383-13456`,
  `:10277-10304`, `:10225-10273`
- **Detail:**
  - (a) `/report` has no membership or existence check. Spec: "The caller must be joined
    to the room to report it." Each report is also an unbounded audit append.
  - (b) `/upgrade` checks only that the caller is joined, and discards the tombstone
    result, so a PL-0 member gets 200 and a new room that names the old one as its
    predecessor.
  - (c) Any joined member can change the directory visibility.
  - (d) Alias `PUT` does not validate the alias grammar or domain, and has no power
    check, so any user can take `#admin:<server>`.
- **Fix:**
  - Require membership for `/report`.
  - Make `/upgrade` fail with 403 unless the tombstone succeeds.
  - Gate directory changes on power level.
  - Validate the alias grammar and require the local domain.
- **Test:** GIVEN a PL-0 member WHEN they call `/upgrade` THEN 403 and no new room exists.

### Area 2 — refuted

- **CSAZ-2, `/state/{type}/{key}` sub-claim.** The gate admits `join` and `leave` only,
  and returns state as of the leave point, as the spec requires ("If the user has left
  the room then the state is taken from the state of the room when they left").

### Area 2 — hardening notes (not verified)

- The sequential room-ID counter is the size of a vector that `rooms.erase` can shrink,
  so a later `createRoom` can collide (`room_service.cpp:2547`, `:3816`).
- `/relations`, `/threads` and the initialSync chunk do not skip rejected or soft-failed
  events (ADR-0064 B2).
- `/user_directory/search` returns every local profile. The spec permits this, but it is
  an enumeration surface.
- Cross-signing uploads do not check the embedded `user_id` or `usage`.

### Area 2 — coverage gaps

- Read by grep only: `src/sync/sync_filter.cpp`, `stream_token.cpp`, `sync_notifier.cpp`
  and `device_list_delta.cpp`.
- Not read: the `src/trust_safety/` internals and the `/sync` leave timeline for departed
  users.

---

## Area 3 — HTTP transport, TLS and request-level DoS

**Result:** 8 findings confirmed (3 high, 3 medium, 2 low). None were refuted; one
additional finding came from the verifier.

**Prior fixes re-checked, all hold:** H-03, M-02, M-03, L-04, L-05 and M-07. Also holding:
- request-smuggling defences: `Transfer-Encoding` refused, duplicate or mismatched
  `Content-Length`, obs-fold, LF-only line endings, closing after a parse error;
- `X-Forwarded-For` handling, walked right to left over trusted proxies;
- response-header CRLF validation;
- JSON depth and member caps, duplicate-key refusal and UTF-8 validation.

**Root cause shared by HTTP-1 and HTTP-2:** the main request pool is a hard-coded 8
threads (`src/main.cpp:742`), and a worker stays tied to its connection through idle,
partial-read and outbound-wait phases.

### HTTP-1 — One client can hold every worker in the main request pool

- **Severity:** high · **Attacker:** A1 · **Verdict:** confirmed (orchestrator re-checked the
  pool size, defaults and the parking loop)
- **Location:**
  - `src/homeserver/http_server.cpp:594-653` (`wait_for_next_request`), `:1653-1737`
    (`serve_connection`), `:811-883` (`read_remaining_body`), `:1322-1346`
  - `include/merovingian/config/config.hpp:64-67`; `src/main.cpp:742`
- **Rule:** the claims this finding contradicts:
  - `docs/threat-model.md:1137-1171` says the parking cap stops "a single client [from
    converting] open sockets into held worker threads beyond the operator's budget", and
    that "the cap bounds one host's share".
  - ADR-0072 says the same of the per-IP connection cap.
- **Path — keep-alive parking (fully protocol-conformant):**
  1. The default `keep_alive_max_connections` is 8, the same as the pool size.
     Validation is range-only and does not relate the two.
  2. A parked connection blocks in `poll()` on its own pool worker.
  3. A client opens 8 connections and sends one small request on each every ~14 s
     (the idle window is 15 s). Each worker serves the request and parks again.
  4. All 8 workers stay occupied indefinitely. New connections wait in the FIFO queue,
     which has no timeout. The cost is about 0.6 requests per second and nothing that
     looks like slowloris.
- **Path — slow body:**
  1. The body deadline is `30 s + Content-Length/16 KiB`, with only a 5 s gap check
     between bytes.
  2. For the two media upload routes, the transport cap rises to `max_upload_size`
     (50 MiB) before authentication.
  3. One byte every 4.9 s therefore holds a worker for about 3230 s. Other POSTs hold
     one for about 94 s.
- **Path — idle connect and handshake:** an idle connect holds a worker for 5 s, a
  dribbled request head for 30 s, and a dribbled TLS ClientHello for 15 s. The TLS
  handshake runs on the worker (`http_server.cpp:2014`).
- **Impact:** 8 sockets from one address stall every client and inbound federation
  request on every listener. The per-IP cap (64) is eight times the pool.
- **Fix:**
  - Stop tying a worker to idle or partial-read phases: park and read request heads on a
    poll/epoll reactor, and dispatch only complete request heads.
  - Enforce a real minimum body rate.
  - Authenticate and rate-limit from the request head before reading any large body.
  - Cap requests and lifetime per connection.
  - Cap worker-holding connections per client well below the pool size, and make the
    pool size configurable.
  - Correct the threat-model text and record the design as an ADR.
- **Test:** GIVEN a pool of N workers WHEN one client holds N keep-alive connections,
  sending one request every idle−1 s, or trickles N request bodies THEN a request from a
  different client completes within 1 s.

### HTTP-2 — Unauthenticated directory endpoints pin workers on blocking outbound federation calls

- **Severity:** high · **Attacker:** A1 · **Verdict:** confirmed
- **Location:**
  - `src/homeserver/client_server.cpp:8892-9036`: `GET` and `POST
    /publicRooms?server=`, and `GET /directory/room/{alias}` for a remote alias
  - `src/homeserver/room_service.cpp:1656-1769`
  - `src/homeserver/worker_pool.cpp:1387-1418`
  - `include/merovingian/config/config.hpp:353`
- **Path:**
  1. These routes are served before the authentication gate.
  2. `perform_sync_outbound_call` runs server discovery, then a federation request,
     synchronously on the request thread. `remote_timeout` defaults to 60 s, and the
     federation-worker round trip waits up to `total_timeout + 10` s.
  3. `RuntimeLockRelease` frees the runtime mutex, not the thread.
  4. No concurrency cap applies to this path.
  5. The generic rate tier allows 90 requests/min, and the alias route escapes it
     entirely through HTTP-3.
- **Spec:** unauthenticated access to these endpoints is permitted, so this is a design
  flaw, not a conformance defect.
- **Impact:** a server under the attacker's control that never answers pins all 8
  workers at about 8 requests per minute. It also makes this server send signed
  requests on the attacker's schedule.
- **Fix:**
  - Run proxy calls on a bounded, separate pool (or asynchronously), with a global and a
    per-client in-flight cap well below the pool size.
  - Use a short deadline and answer 429 or 502 when saturated.
  - Consider an operator switch, or requiring authentication, for remote proxying.
- **Test:** GIVEN a peer that never answers WHEN 20 unauthenticated
  `publicRooms?server=` requests arrive THEN `/versions` still answers promptly AND the
  requests over the cap get 429.

### HTTP-5 — SIGPIPE is not ignored in the server, so a TLS client that resets its connection can kill the process

- **Severity:** high (medium where systemd's default `IgnoreSIGPIPE=yes` applies) ·
  **Attacker:** A1 · **Verdict:** confirmed by code reading, not reproduced
- **Location:**
  - `src/main.cpp`: no SIGPIPE handling.
  - `src/homeserver/tls.cpp:165-166`, `:290`: `SSL_set_fd` gives OpenSSL's socket BIO,
    which uses `write()` without `MSG_NOSIGNAL`.
  - `src/homeserver/http_server.cpp:1171-1176`, `:1276-1287`: an error response is
    written after a failed read.
  - `src/media/thumbnailer.cpp:470`: the only `SIG_IGN`, reached lazily on the first
    thumbnail.
- **Rule:** `docs/hardening.md:174-178` says "`SIGPIPE` is ignored so a worker that dies
  mid-request cannot terminate the parent". The server does not do this at startup.
- **Path:**
  1. The client completes a TLS handshake and sends a partial request head, then resets
     the connection.
  2. The read fails, and the server writes a 408 through `SSL_write_ex`.
  3. That `write()` returns `EPIPE` and raises SIGPIPE. The default disposition
     terminates the process.
  4. The plain-HTTP and IPC paths use `MSG_NOSIGNAL` and are not affected.
  5. `tests/integration/test_main.cpp:15` ignores SIGPIPE for the whole test binary,
     which hides the defect.
- **Exposure:** exposed under OpenRC, BSD `rc.d`, containers and manual runs. The shipped
  systemd unit relies on the systemd default; it sets nothing itself.
- **Impact:** one unauthenticated TLS connection terminates the homeserver.
- **Fix:** set `sigaction(SIGPIPE, SIG_IGN)` in each executable's `main()` (server,
  federation worker, thumbnail worker, `db-migrate`) before any thread starts.
- **Test:** GIVEN the server started with the default SIGPIPE disposition and a TLS
  listener WHEN a client sends a partial request head and resets THEN the process
  survives and serves the next request. The test must not inherit the harness's
  `SIG_IGN`.

### HTTP-3 — Rate-limit buckets are keyed on the raw path, so varying a path segment bypasses them

- **Severity:** medium · **Attacker:** A1 and A2 · **Verdict:** adjusted; the auditor
  understated the scope
- **Location:** `src/homeserver/client_server.cpp:2651-2742` (`normalized_target`),
  `:2779-2811`; `include/merovingian/http/rate_limit.hpp:338-376`
- **Rule:** `docs/http-transport.md:490-492`, `:546` says path parameters such as media
  IDs are coalesced.
- **What is coalesced:** only the room ID (not the suffix after it), the device ID, the
  user ID in `/user/{userId}/…`, profile, join, knock, v1 relations and
  `/_matrix/client/v1/media/*`.
- **What is not coalesced:**
  - `/_matrix/media/v3/download|thumbnail/{server}/{id}`
  - `/directory/room/{alias}`
  - `sendToDevice/{type}/{txnId}`
  - the `send/{type}/{txnId}`, `state/…` and `redact/…` suffixes
  - unknown paths
- **Detail:**
  - The per-user key embeds the same normalised path. Varying `txnId` therefore gives a
    fresh per-IP and per-user bucket for every message send, so message sending is
    effectively not rate-limited.
  - At 100 000 keys, every new key runs two linear passes in `evict_to_make_room` while
    the global runtime mutex is held.
  - The auditor's "`thirdparty` exempt before auth" claim is narrower than stated:
    unauthenticated callers still get 401. Authenticated users can drive unlimited
    appservice lookups, which is by design and low.
- **Fix:**
  - Key buckets on a matched route template; send unmatched paths to one shared bucket.
  - Make eviction O(1) (LRU or CLOCK), and move `allow()` ahead of the global mutex.
  - Correct `docs/http-transport.md`.
- **Test:**
  - GIVEN a media tier of 20/min WHEN one IP fetches 100 distinct
    `/_matrix/media/v3/download/x/<id>` THEN the requests over 20 get 429.
  - GIVEN a message tier WHEN one user sends 200 messages with distinct `txnId` THEN the
    tier cap applies.

### HTTP-4 — `/sync` `timeout` has no upper bound and there is no per-user cap on long polls

- **Severity:** medium · **Attacker:** A2 · **Verdict:** confirmed
- **Location:**
  - `src/homeserver/client_server.cpp:3763-3773`, `:4568`
  - `src/sync/sliding_sync_parser.cpp:521-538` (digit accumulation without an overflow
    check)
  - `src/homeserver/http_server.cpp:1450-1644`
- **Detail:**
  - One account opens 32 long polls with enormous `timeout` values and fills the 32-thread
    sync pool.
  - A queue-full submit falls back to blocking a main-pool worker for the requested
    time.
  - `std::chrono::milliseconds{uint64}` above 2^63 wraps negative. `now() + ms` above
    about 9.2e12 ms overflows signed nanoseconds, which is undefined behaviour.
  - A clamp alone is not enough: 64 thirty-second polls a minute still fit the rate tier.
- **Fix:**
  - Clamp `timeout` to a server maximum using saturating arithmetic, and do the same in
    the sliding-sync parser.
  - Cap concurrent long polls per user and device, replacing an older poll from the same
    device.
- **Test:** GIVEN a 32-thread sync pool WHEN one user issues 40 `/sync` requests with huge
  `timeout` values THEN each returns by the server maximum AND another user's `/sync` is
  served.

### HTTP-8 — Keep-alive connections have no request-count or lifetime limit

- **Severity:** medium (it is what makes HTTP-1's parking variant indefinite) ·
  **Attacker:** A1 · **Verdict:** found by the verifier
- **Location:** `src/homeserver/http_server.cpp:1653-1710`
- **Fix:** close a connection after N requests or T seconds. This fix belongs with HTTP-1.
- **Test:** GIVEN a keep-alive connection WHEN it sends more requests than the
  per-connection cap THEN the server closes it after the cap.

### HTTP-6 — Unauthenticated media bodies up to 50 MiB are buffered and copied before authentication

- **Severity:** low · **Attacker:** A1 · **Verdict:** adjusted from medium
- **Location:** `src/homeserver/http_server.cpp:1322-1346`;
  `src/homeserver/client_server.cpp:8702`
- **Detail:**
  - The transport reads the whole body.
  - The dispatcher copies it (`auto req = raw_req`) before the 401 is returned.
  - Peak memory is about 800 MiB across 8 workers. It is only allocated as bytes arrive,
    so it costs the attacker the bandwidth.
- **Fix:** raise the transport body cap only after the request head has authenticated.
- **Test:** GIVEN no token WHEN a client declares a 50 MiB `Content-Length` to the upload
  route THEN it gets 401 after reading at most a bounded prefix.

### HTTP-7 — `parse_json` wraps integers above `INT64_MAX` to negative values

- **Severity:** low (a data-fidelity quirk, not a memory-safety issue) ·
  **Verdict:** adjusted
- **Location:** `src/canonicaljson/yyjson_adapter.c:168-176`;
  `src/canonicaljson/parser.cpp:184-190`
- **Detail:**
  - Client bodies and signed paths use `parse_lossless`, which range-checks integers.
  - The permissive `parse_json` parses room-tag bodies, stored account data, and some
    remote and appservice responses.
- **Fix:** reject unsigned values above the canonical range in the adapter.
- **Test:** GIVEN `18446744073709551615` WHEN `parse_json` parses it THEN the result is
  `integer_out_of_range`.

### Area 3 — hardening notes (not verified)

- `%00` decodes to a NUL byte in path and query values (`src/core/query_params.cpp:56-99`).
- Transport error bodies are plain text but are labelled `application/json`.
- The 1 MiB transport cap is below the largest legal federation `/send` (50 PDUs of
  64 KiB each).
- `TlsConnection::pump` grants a fresh 15 s per read.
- TLS 1.2 session-ticket keys are never rotated.
- `OutboundClient` relies on callers to keep CR/LF out of header values.
- `accept4` returning `EMFILE` only sleeps; there is no reserve descriptor.
- The main pool and the sync pool sizes are not configurable.

### Area 3 — coverage gaps

- Not read: `src/net/listener.cpp`, the canonical JSON serializer,
  `federation_proxy.cpp`, and the service launchers under `packaging/`.

---

## Area 4 — Federation inbound

**Result:** 12 findings confirmed: 1 critical, 5 high, 3 medium, 3 low. The spec citation
for FED-2 was corrected. One sub-claim of FED-6 was refuted.

**Prior fixes that hold:**
- H-04, M-04 and M-05.
- Signature and hash checks on `send_*` and invite (#461, #462).
- L-06 for `/backfill`.
- ADR-0071: main re-verifies PDUs, invites and memberships that the worker relays.
  EDU frames are not covered (FED-12).

### FED-1 — `send_join` response events are not bound to the room being joined, and events from our own domain skip signature checks

- **Severity:** critical
- **Attacker:** A2 (any local user) working with A3 (a server they control)
- **Verdict:** confirmed; the orchestrator re-checked both halves in code
- **Location:**
  - `src/homeserver/room_service.cpp:3138-3315` (`filter_verified_send_join_events`;
    own-domain shortcut at `:3244-3248`)
  - `:3016-3136` (`ingest_send_join_state`; room ID taken from each event at `:3078-3097`)
  - `:3944-4055` (auth-chain loop), `:4253-4255` (background path)
  - `src/database/persistent_store.cpp:1772-1899` (`prepare/apply_store_event_with_state`)
- **Spec:** "Checks performed on receipt of a PDU … 2. Passes signature checks, otherwise
  it is dropped." Project rule: `src/federation/AGENTS.md` rules 2 and 4.
- **Path:**
  1. A local user calls `POST /join/!x:evil.example?server_name=evil.example`. The
     `via` and `server_name` values supplied by the client are accepted as join
     candidates (`room_service.cpp:2973`).
  2. evil.example's `send_join` response includes, in `state` or `auth_chain`, an
     `m.room.power_levels` event whose `room_id` is L, a room hosted here that the user
     is in. The event gives the user power level 100 and names a sender on our domain.
  3. `filter_verified_send_join_events` accepts it without any signature check, because
     the sender's domain is ours. The unit test at
     `tests/unit/test_federation_invite_join.cpp:1979-2012` pins that behaviour.
     Events signed by evil.example for its own users with `room_id = L` also pass.
  4. `ingest_send_join_state` stores each event under that event's own `room_id`.
     Nothing compares it with the room being joined. `state_matches_event` compares the
     event only with itself, and no auth rules run.
  5. `prepare_store_event_with_state` issues `UPDATE current_state` whatever the event's
     status, so a stored "outlier" still replaces L's current state.
  6. `compose_signed_event` builds and authorises every subsequent local event in L from
     `store.state` (`room_service.cpp:1026`, `:1223-1258`, `:1497-1500`). The forged
     power levels are now the rules for the room.
- **Impact:**
  - Any local user can make themselves admin of any local room.
  - Any local user can forge membership for other users, including the victims of
    bans, via the background path.
  - The forged state persists until a later inbound federation event triggers
    `recompute_current_state` for L.
  - Local events sent in that window name forged auth events, so remote servers reject
    them and the room diverges.
- **Documentation:** `docs/threat-model.md:496-521` says a bad-faith resident server
  "degrades the joining server's view of the room rather than being able to inject
  forged state". That is not true.
- **Fix:**
  - Drop every `state` and `auth_chain` entry whose `room_id` (or, for v12
    `m.room.create`, whose derived room ID) is not the room being joined.
  - Never accept an own-domain event without a signature check. A resident server has
    no reason to send us events we authored that we do not already hold.
  - Ingest the join snapshot without writing `current_state` for any other room.
  - Correct the threat model.
- **Test:** GIVEN local room L with power levels P, and a mock resident server whose
  `send_join` `state` holds (a) an unsigned `m.room.power_levels` for L with an
  own-domain sender and (b) one signed by the mock server WHEN a local user joins
  `!x:mock` through it THEN L's current state and memberships are unchanged AND neither
  event is stored.

### FED-2 — Federation read endpoints do not check that the requesting server is in the room

- **Severity:** high · **Attacker:** A3 · **Verdict:** confirmed; spec citation corrected
- **Location:**
  - `src/federation/inbound_request.cpp:1250-1280`, `:1452-1544`, `:2329-2386`
  - `src/homeserver/local_http_router.cpp:2182-2232`
  - `src/federation/event_query.cpp:248-256`, `:297-558`
- **Spec:**
  - `GET /state_ids` lists "403 | The requesting host is not in the room, or is excluded
    from the room via `m.room.server_acl`."
  - `/state`, `/event`, `/backfill` and `/get_missing_events` have no 403 row. A
    membership rule for those is therefore a security requirement, not a spec MUST.
    The ACL MUST is implemented, except on `/event`, which is not in the spec's ACL list.
- **Path:**
  1. The room-scoped providers take no origin. The only gate is the server ACL.
  2. `/state` and `/state_ids` fall back to the current state for an unknown `event_id`.
  3. `/get_missing_events` ignores `earliest_events` and `latest_events` and has no cap
     on `limit`. It returns every event in the room at or above `min_depth`, which is the
     full history in one request, scanned O(N) under the runtime lock.
  4. `/event/{id}` returns any stored event.
- **Impact:** any federating server that knows a room ID can dump the state, the member
  list and the entire history of any room hosted here, including private rooms.
  Encrypted rooms leak metadata and ciphertext.
- **Fix:**
  - Pass the authenticated origin to every provider. Require the origin to have a
    joined member, or history visibility that permits it, and answer 403
    `M_FORBIDDEN` otherwise.
  - Resolve `/event` through the event's room.
  - Implement `/get_missing_events` as a walk from `latest_events`, with a capped
    `limit`.
  - Return 404 for an unknown `event_id` instead of falling back.
- **Test:** GIVEN a room with only local members WHEN another server calls `/state`,
  `/state_ids`, `/event`, `/backfill` and `/get_missing_events` for it THEN each returns
  403 and no room data.

### FED-3 — The sender of an `m.direct_to_device` EDU is not bound to the sending server

- **Severity:** high · **Attacker:** A3 · **Verdict:** confirmed
- **Location:** `src/homeserver/local_http_router.cpp:1053-1107`;
  `src/federation/inbound_ingestion.cpp:290-293`
- **Detail:**
  - The EDU's `sender` is stored as given. Typing, receipt and device-list EDUs do check
    the sender with `user_belongs_to_origin`; this one does not.
  - Targets are not checked to be local users.
  - `message_id` is never read. The spec says it is "used for idempotence".
- **Impact:**
  - Any peer can deliver to-device messages (verification requests, key requests) that
    appear to come from any user on any server.
  - Invented targets grow the queue without bound (compare CSAZ-10).
- **Fix:**
  - Require `server_name(sender) == origin`.
  - Deliver only to local users.
  - Deduplicate on `(origin, message_id)`.
  - Cap fan-out per EDU.
- **Test:** GIVEN origin B WHEN it sends a to-device EDU with `sender=@x:A` to a local
  user THEN nothing is queued AND a replayed `message_id` from a valid sender is
  delivered once.

### FED-4 — Forged X-Matrix requests lock a real peer out of federation until restart

- **Severity:** high · **Attacker:** A1 (no credential needed) · **Verdict:** confirmed
- **Location:** `src/federation/inbound_request.cpp:2263-2324`, `:2519`, `:2624`, `:2978`;
  `src/federation/security.cpp:313-320`
- **Path:**
  1. The attacker sends a request naming `origin=peer.example` with a real key ID and a
     garbage signature.
  2. `check_inbound_request_signature` increments the claimed origin's
     `consecutive_failures`.
  3. After three such requests, `remote_trust_policy` answers 429 for that origin. It
     does so before the signature check, so it applies to every genuine request too.
  4. The counter is reset only after an accepted request, which can no longer happen,
     and nothing decays it.
  5. The unit test at `tests/unit/test_federation_inbound_request.cpp:743-771` asserts
     the lockout without modelling a third party.
- **Impact:** three unauthenticated packets cut federation with any peer. This is a side
  effect of the earlier H-04 fix.
- **Fix:**
  - Never charge a failed signature to the claimed origin's trust record; count it
    against the source address or the key-resolution budget instead.
  - Decay origin-level backoff over time.
- **Test:** GIVEN a known peer P WHEN 10 bad-signature requests naming P arrive from
  another address THEN a correctly signed request from P is accepted.

### FED-5 — An inbound `/invite` for a room hosted here overwrites a ban with a forged invite

- **Severity:** high · **Attacker:** A3 (with a banned local accomplice) · **Verdict:**
  confirmed; the URL event-ID sub-claim is mitigated by the worker relay
- **Location:** `src/homeserver/local_http_router.cpp:681-703`, `:2049-2154`
- **Path:**
  1. `invite_handler` checks the event shape, that the target is local and that the
     sender is on the origin. It runs no room auth rules.
  2. It rewrites the target's membership row from `ban` to `invite`, and stores the
     forged event as the target's current `m.room.member` state.
  3. The banned user then joins. Local composition authorises against `store.state`,
     sees `invite`, and allows the join even in an invite-only room.
- **Impact:** any remote server can undo a ban for a local user in a room hosted here.
- **Fix:**
  - When the room is known locally, run the room's auth rules on the invite and refuse
    it on failure; never overwrite a ban.
  - Keep remote invite events out of `current_state`.
  - Bind the URL event ID to the computed ID on the direct path too.
- **Test:** GIVEN local user U banned in local room L WHEN a remote server sends a
  validly signed invite for U into L THEN U stays `ban`, L's state is unchanged, and the
  response is 403.

### FED-7 — Device-list and signing-key EDUs write one row per local user, with no deduplication, under the global lock

- **Severity:** high (DoS) · **Attacker:** A3 · **Verdict:** confirmed
- **Location:**
  - `src/homeserver/local_http_router.cpp:1473-1507`
  - `src/database/persistent_store.cpp:2945-2968`
  - `src/homeserver/worker_pool.cpp:829-840`
- **Detail:**
  - Each EDU records a change for every local user, not only those who share a room with
    the subject.
  - Rows are neither deduplicated nor pruned.
  - Each insert is synchronous and runs under the runtime mutex.
  - At the default 1200 EDUs per minute per origin, that is 1200 × (local users) rows a
    minute.
- **Fix:**
  - Notify only users who share a room with the subject, and deduplicate on
    (observer, subject).
  - Prune old rows.
  - Weight the rate limit by fan-out.
  - Do not hold the runtime mutex across per-user writes.
- **Test:** GIVEN N local users WHEN 100 identical device-list EDUs arrive for a remote
  user who shares no room THEN no rows are written.

### FED-6 — `send_join`, `send_leave` and `send_knock` skip the spec's event validation, and the membership recorded comes from the endpoint

- **Severity:** medium · **Attacker:** A3 · **Verdict:** adjusted · **Status:** fixed in 0.12.19
- **Refuted part:** "no auth check". `membership_acceptor` authorises the event before
  writing it (`local_http_router.cpp:1771-1857`, `:1866-1924`).
- **Location:** `src/federation/inbound_request.cpp:948-1097`;
  `src/homeserver/local_http_router.cpp:705-716`, `:1513-1627`
- **Spec:** "The receiving server MUST apply certain validation before accepting the
  event". The listed conditions include: the event type is not `m.room.member`, the
  content `membership` does not match the endpoint, the event sender is not a user ID on
  the origin server, and the `state_key` is not equal to the `sender`. For `make_*`,
  `userId` "MUST be a user ID on the origin server".
- **Path:**
  1. In a room with a knock join rule, a remote user signs a `membership: knock` event
     and PUTs it to `send_join`.
  2. The event passes auth as a knock.
  3. `membership_for_endpoint` records `join`, and the user is added to
     `LocalRoom.members`. That list drives which servers receive fan-out, so the
     knocker's server now gets every PDU and EDU for the room.
- **Fix:**
  - Enforce the listed validations.
  - Derive the membership from the event content and reject a mismatch with the
    endpoint.
  - Apply the origin check on `make_*`.
- **Test:** GIVEN a knock room WHEN a knock event is PUT to `send_join` THEN 400
  `M_INVALID_PARAM`, with no membership row and no fan-out destination.

### FED-8 — Receipt EDUs bypass the server ACL

- **Severity:** medium (spec MUST) · **Attacker:** A3 · **Verdict:** confirmed
- **Location:** `src/federation/inbound_request.cpp:2388-2420`, `:2933-2952`;
  `src/homeserver/local_http_router.cpp:1033-1039`, `:1288-1381`
- **Spec:** "For receipts (`m.receipt`), all receipts for a particular room ID MUST be
  ignored if the sending server is denied access to the room identified by that ID."
- **Detail:**
  - `room_id_from_edu_content` looks for a top-level `room_id` member, but receipt
    content is keyed by room ID, so the ACL check never fires.
  - The receipt sink accepts any room with any local membership row, and does not
    require the receipt's user to be joined.
- **Fix:**
  - Apply the ACL to each room key in the receipt content.
  - Require the receipt's user to be joined.
- **Test:** GIVEN a room whose ACL denies evil.example WHEN evil.example sends a receipt
  for that room THEN nothing is stored.

### FED-11 — PDUs for rooms with no local membership are stored without bound

- **Severity:** medium (low-medium) · **Attacker:** A3 · **Verdict:** adjusted
- **Location:** `src/homeserver/local_http_router.cpp:3564-3849`
- **Detail:**
  - No "room known here" gate exists. Such PDUs are stored as rejected, and they are
    never pruned.
  - The spoofing risk is limited: create-event auth ties the room ID's domain to the
    sender for versions up to 11, and v12 room IDs are hashes.
- **Fix:** drop PDUs for rooms with no local membership or invite unless they answer an
  outstanding backfill.
- **Test:** GIVEN no local member of `!x:evil` WHEN 50 PDUs for it arrive THEN none are
  stored.

### FED-9 — A transaction whose first PDU has no `room_id` is processed in the main process, outside the worker sandbox

- **Severity:** low (defence in depth) · **Attacker:** A3 · **Verdict:** adjusted from
  medium
- **Location:** `src/homeserver/federation_request_routing.cpp:105-133`, `:179-187`;
  `src/homeserver/federation_proxy.cpp:142-150`
- **Fix:** bypass the worker only when `pdus` is present and empty.
- **Test:** GIVEN a `/send` whose first PDU lacks `room_id`, followed by real PDUs WHEN it
  arrives THEN it is routed to the worker.

### FED-10 — Resolving sender keys for relayed PDUs bypasses the key-resolution admission budget

- **Severity:** low · **Attacker:** A3 (authenticated) · **Verdict:** adjusted
- **Location:** `src/federation/inbound_request.cpp:2660-2726`;
  `src/federation/remote_key_cache.cpp:457-529`
- **Detail:** each transaction can trigger up to 50 discovery and key fetches to domains
  of the attacker's choosing, with no negative cache.
- **Fix:** route this through the same admission budget and failure cache as the
  unknown-remote path.
- **Test:** GIVEN 50 unresolvable sender domains in one transaction WHEN it is processed
  THEN outbound fetches stay within the budget.

### FED-12 — The main process trusts the `origin` of EDU frames relayed by the worker

- **Severity:** low (A5 hardening) · **Verdict:** found by the verifier
- **Location:** `src/homeserver/worker_pool.cpp:811-842`
- **Detail:** ADR-0071 re-verification covers PDUs and memberships, not EDUs. A
  compromised worker can forge typing, receipt, device-list and to-device EDUs from any
  origin.
- **Fix:** bind the envelope origin to the origin main verified for the in-flight
  request.
- **Test:** GIVEN a worker relaying an EDU frame whose `origin` differs from the verified
  request origin WHEN main handles it THEN the EDU is rejected.

### Area 4 — hardening notes

- `old_verify_keys` are ignored, so events signed with a rotated-out key cannot be
  verified. This affects availability only.
- Remote key IDs are not required to start with `ed25519:`.
- Sender-domain parsing exists in three differing implementations (`inbound_request.cpp`,
  `worker_pool.cpp:639`, `local_http_router.cpp:2836`). Consolidate them to avoid
  differential parsing.
- `server_name_is_valid` requires a `.`, and the X-Matrix scheme comparison is
  case-sensitive.
- The `send_join` response never adds `join_authorised_via_users_server` for restricted
  rooms (already a recorded capability gap).
- `event_auth` is unimplemented.

### Area 4 — coverage gaps

- Read only in part: `outbound_membership.cpp`, `outbound_transaction.cpp`,
  `dispatch_worker.cpp`, the worker event loop beyond provider wiring, and media
  federation download.
- Unrouted, not audited: `/publicRooms`, `/timestamp_to_event` and `/openid/userinfo`.

---

## Area 5 — Event engine (auth rules, state resolution, redaction, canonical JSON)

**Result:** 12 findings confirmed: 5 high, 4 medium, 3 low. None refuted; 5 were adjusted
downward.

**Why these matter:** every finding is a divergence from the spec algorithm. When this
server accepts an event that conformant servers reject, or resolves state differently,
the room splits, and the local view of power levels and bans is wrong.

**Prior fixes that hold:**
- H-05, H-06, L-14 and L-15.
- H-07 holds for `users` and scalar keys, but not for the `events` map (EVT-11).
- #487 rule fixes: scalar power level 9.5, create validation, the `@` state-key rule,
  third-party-invite signatures, and v12 creators in `users`.

### EVT-1 — Auth rule "`join_authorised_via_users_server` must be signed by that user's server" is not enforced

- **Severity:** high · **Attacker:** A3 · **Verdict:** confirmed
- **Location:**
  - `src/events/authorization.cpp:1069-1099`
  - `src/federation/inbound_request.cpp:1962-2020`
  - `src/federation/security.cpp:260-284`
  - `src/homeserver/room_service.cpp:3299`
- **Spec:** `rooms/v8.md` rule 4.2 (v9–v11 rule 4.2, v12 rule 5.2): "If `content` has a
  `join_authorised_via_users_server` property: 1. If the event is not validly signed by
  the homeserver of the user ID denoted by the key, reject."
- **Path:**
  1. The restricted-join branch checks only that the named user is joined and has invite
     power. The authoriser receives no signature material.
  2. PDU verification checks only the sender server's signature.
  3. No code path verifies a signature keyed on `join_authorised_via_users_server`.
- **Impact:** any remote server can join its users to any restricted or
  `knock_restricted` room by naming any joined member with invite power (the default
  invite level is 0). The room's `allow` conditions are bypassed.
- **Fix:**
  - At PDU receipt and in `send_join`, require a valid signature from the named user's
    server whenever the key is present, and fail closed if that server's key cannot be
    fetched.
  - Record the verified result on the event so that state-resolution re-authorisation
    uses it.
- **Test:** GIVEN a v10 restricted room with `@admin:us` joined WHEN a join from
  `@evil:a3` names `@admin:us` and is signed only by a3 THEN it is rejected AND the same
  join also signed by `us` is accepted.

### EVT-2 — `m.room.power_levels` events are not held to `events["m.room.power_levels"]`

- **Severity:** high · **Attacker:** A3, or a local moderator · **Verdict:** confirmed
  (orchestrator re-checked)
- **Location:** `src/events/authorization.cpp:1343-1503`; the return at `:1490-1503` uses
  `state_default` only.
- **Spec:**
  - `rooms/v12.md` rule 8 (v11 rule 7): "If the event type's *required power level* is
    greater than the `sender`'s power level, reject."
  - The required level is "listed explicitly in the `events` section or given by either
    `state_default` or `events_default`."
- **Path:**
  1. In a default room, power-level events require level 100 and `state_default` is 50.
  2. A level-50 moderator sends a power-levels change within the bounds of rule 9 or 10,
     such as lowering `kick`, raising `users_default`, or promoting users below 50.
  3. The code compares only against `state_default` and allows it.
- **Existing test:** `tests/conformance/test_event_auth_rules.cpp` (scenario "Auth rules
  allow a power_levels change where both old and new scalar values are within the
  sender's power", around `:3060-3090`) asserts the non-conformant result and must be
  corrected.
- **Impact:** moderators can rewrite the power-level map where the spec says only admins
  can. Conformant servers reject these events, so the room diverges.
- **Fix:** compute the required level (the `events[type]` value, else `state_default`)
  before the power-levels-specific rules.
- **Test:** GIVEN `events{"m.room.power_levels":100}`, `state_default` 50 and a sender at
  50 WHEN the sender changes `users_default` THEN the event is rejected.

### EVT-3 — With three or more state groups, a conflicted key lands in both maps and the last group wins

- **Severity:** high · **Attacker:** A3 (controls `prev_events`) and organic forks ·
  **Verdict:** confirmed (orchestrator traced the loop)
- **Location:** `src/events/state_resolution.cpp:929-955`, `:1503-1506`
- **Spec:** "If a given key *K* is present in every *Si* with the same value *V* in each
  state map, then the pair (*K*, *V*) belongs to the *unconflicted state map*. Otherwise,
  *V* belongs to the *conflicted state set*."
- **Path:** for the groups `[K=A]`, `[K=B]`, `[K=A]`:
  1. The first group inserts A.
  2. The second group moves K to `conflicted`.
  3. The third group finds K absent from `unconflicted` and re-inserts A.
  4. Step 5 then overwrites the resolved value with the "unconflicted" one.
  - The same happens for `A,B,B` and `A,B,C`: whichever group comes last wins.
- **Impact:** for keys present in every fork (power levels, join rules, each member),
  resolution is replaced by prev-event order. A ban in one of three forks can be dropped.
  No test uses more than two groups.
- **Fix:** build `key → set(event_id)` with a per-key group count. A key is unconflicted
  only if it appears in every group with exactly one ID.
- **Test:** GIVEN three groups with `member(@u)` as join, ban, join WHEN partitioned THEN
  the key is only conflicted AND the result does not depend on group order.

### EVT-4 — Reverse topological power ordering is a plain sort, not a topological sort

- **Severity:** high · **Attacker:** A3 · **Verdict:** confirmed (orchestrator
  re-checked)
- **Location:** `src/events/state_resolution.cpp:960-999`
- **Spec:** "the lexicographically smallest topological ordering based on the DAG formed
  by auth events … sorting the events using Kahn's algorithm for topological sorting, and
  at each step selecting, among all the candidate vertices, the smallest vertex using the
  above comparison relation."
- **Path:**
  1. `std::stable_sort` orders by power, then timestamp, then ID, ignoring auth-event
     dependencies between candidates.
  2. Example: an admin's ban cites a moderator's earlier kick as an auth event. The ban
     is applied first, then the kick is re-applied over it, and the ban is lost.
- **Fix:** Kahn's algorithm over the auth DAG restricted to the set, choosing the minimum
  ready vertex by (power descending, timestamp ascending, event ID ascending).
- **Test:** GIVEN conflicted events where the higher-power event cites the lower-power one
  in `auth_events` WHEN they are ordered THEN the cited event comes first.

### EVT-6 — Negative user power levels are replaced by `users_default`

- **Severity:** high · **Attacker:** A2 or A3 (a muted user) · **Verdict:** confirmed
  (orchestrator re-checked)
- **Location:** `src/events/authorization.cpp:148-154` (-1 used as the "absent" value),
  `:831`, `:1442-1446`, `:1462-1466`
- **Spec:** "If a `user_id` is in the `users` list, then that `user_id` has the associated
  power level"; `users_default` applies to users "not mentioned in the `users` key". The
  allowed range is `[-(2**53)+1, (2**53)-1]`.
- **Detail:**
  - A user set to -1 (the usual client "mute") gets `users_default`, so their messages
    pass `events_default` 0.
  - If `users_default` is higher, a muted user is effectively promoted.
  - The same value feeds the kick, ban, invite and power-level target rules.
- **Fix:** return `std::optional<int64_t>` from the `users` lookup and fall back only when
  the user is absent.
- **Test:** GIVEN `users{"@u":-1}` and `events_default` 0 WHEN @u sends a message THEN it
  is denied.

### EVT-5 — Mainline ordering sees only the events inside the submitted state groups

- **Severity:** medium · **Attacker:** A3 · **Verdict:** adjusted from high
- **Location:** `src/events/state_resolution.cpp:106-138`, `:1246`, `:1489`;
  `src/homeserver/state_bookkeeping.cpp:186`, `:312`
- **Spec:** "Repeatedly fetch *Pi+1*, the `m.room.power_levels` event in the `auth_events`
  of *Pi*".
- **Detail:**
  - `power_levels_auth_ancestor` only searches the state-group index and never uses
    `event_lookup`, so the mainline collapses to the current power-levels event.
  - Events based on older power levels are then ordered by timestamp, which the sender
    controls.
  - Iterative auth checks still gate each event, so the effect is divergence, not
    bypass.
- **Fix:** walk the mainline through the `AuthChainEventSource`, failing closed if an
  event is missing.
- **Test:** GIVEN a power-levels chain P2→P1→P0 where only P2 is in the groups WHEN the
  mainline is ordered THEN events based on P0 and P1 get positions 2 and 1.

### EVT-7 — v11 and v12 creator logic reads `content.creator`, which those versions removed

- **Severity:** medium · **Attacker:** A3 / organic · **Verdict:** adjusted from high
- **Location:** `src/events/authorization.cpp:739-745`, `:1010-1017`, `:1292-1299`;
  `src/homeserver/room_service.cpp:2469`
- **Spec:** `rooms/v11.md`: "The `content` of a `m.room.create` event no longer has a
  `creator` property"; "If the only previous event is an `m.room.create` and the
  `state_key` is the sender of the `m.room.create`, allow."
- **Detail:**
  - For v11 and v12 rooms created elsewhere, the creator's first join and first
    power-levels event fail when re-authorised locally (state-resolution auth
    difference, backfill).
  - Locally created rooms always include `creator`, which is why the conformance
    fixtures (`test_event_auth_rules.cpp:17-63`) do not catch this.
- **Fix:**
  - For v11+, derive the creator from the create event's sender, plus
    `additional_creators` in v12.
  - Require `prev_events == [create]` for the bootstrap join.
  - Stop writing `creator` for v11+.
- **Test:** GIVEN a v11 create event without `creator` WHEN the creator's join with
  `prev_events=[create]` is authorised THEN it is allowed.

### EVT-8 — In v12 power ordering, room creators rank at the default power level

- **Severity:** medium · **Attacker:** A3 · **Verdict:** confirmed
- **Location:** `src/events/state_resolution.cpp:558-604`, `:624-633`
- **Detail:**
  - v12 events never list the create event in `auth_events`, so `context->create` is
    null.
  - `user_is_room_creator` returns false, so a creator's actions are ordered as if the
    creator had default power instead of infinite power.
  - The auth check itself derives the create event from the room ID correctly.
- **Fix:** pass the create event derived from the room ID into `power_level_from_event`
  for v12.
- **Test:** GIVEN a v12 room where a creator's ban and an admin's power-levels edit
  conflict WHEN ordered THEN the creator's event is first.

### EVT-9 — The conflicted-state-subgraph walk enumerates paths without memoisation and fails closed

- **Severity:** medium (availability) · **Attacker:** A3, and large legitimate v12 rooms
  · **Verdict:** confirmed
- **Location:** `src/events/state_resolution.cpp:424-488`;
  `include/merovingian/events/limits.hpp:63`
- **Detail:**
  - A recursive DFS with no visited set shares one 20 000-visit budget across all start
    nodes.
  - When the budget runs out, resolution fails, `compute_state_before` returns not-ok,
    and `recompute_current_state` leaves state unchanged.
  - A v12 room with a persistent fork can therefore stop applying bans and power-level
    changes.
- **Fix:** compute the subgraph as the intersection of "reachable from a conflicted
  event" and "reaches a conflicted event" with memoised DAG traversal, and cap distinct
  events only.
- **Test:** GIVEN a 30-rung power-levels ladder and 100 conflicted member events WHEN v12
  resolution runs THEN it resolves within the distinct-event cap.

### EVT-11 — String-valued levels in the `events` map are ignored in v3–v9

- **Severity:** low (upper end) · **Attacker:** A3 · **Verdict:** adjusted from medium
- **Location:** `src/events/authorization.cpp:1538`, `:1573`
- **Spec:** `rooms/v9.md`: string encoding "includes the nested values within the
  `events`, `notifications` and `users` properties."
- **Fix:** use `power_level_member(..., allow_strings)` at both sites.
- **Test:** GIVEN a v9 room with `events{"m.room.topic":"100"}` WHEN a user at level 50
  sets the topic THEN it is denied.

### EVT-10 — A non-object `content.third_party_invite` is treated as absent

- **Severity:** low · **Attacker:** A3 with invite power · **Verdict:** adjusted from medium
- **Location:** `src/events/authorization.cpp:1157-1164`
- **Spec:** "If `content.third_party_invite` does not have a `signed` property, reject."
- **Fix:** enter the third-party branch whenever the key is present.
- **Test:** GIVEN a sender with invite power WHEN an invite carries
  `third_party_invite: "x"` THEN it is denied.

### EVT-12 — Smaller rule divergences

- **Severity:** low · **Verdict:** (a) and (c) confirmed, (b) documented, (d) not verified
- **(a) Missing v3–v5 `m.room.aliases` rule.** `rooms/v3.md`: "If sender's domain doesn't
  match `state_key`, reject. 3. Otherwise, allow." It is absent from
  `authorization.cpp`.
- **(b) A creator with no member event is treated as joined.**
  `src/events/authorization.cpp:1292-1299`. This deviation is documented in
  `docs/event-engine.md:119`.
- **(c) Rejected auth events are not refused.** Rule "If there are entries which were
  themselves rejected under the checks performed on receipt of a PDU, reject" is not
  checked in `validate_auth_events_selection`
  (`src/homeserver/local_http_router.cpp:~365-400`) or in the resolver's
  `find_own_auth_event` (`src/events/state_resolution.cpp:646-681`).
- **(d) v3–v5 are stricter than the spec on scalar power-level values.** This fails
  closed.
- **Also noted by the verifier:** rule 4.2 applies to any membership that carries the key,
  but the code reads the key only in the restricted-join branch.

### Area 5 — hardening notes

- `resolve_state()` (`state_resolution.cpp:849-905`) is a v1-style depth-ordered resolver.
  It is exported but unused. Remove it so it cannot be wired to a v3+ room.
- `redact_event` copies `content` unredacted when `type` is not a string
  (`redaction.cpp:180`). Return an error instead.
- `parse_lossless` is strict for every room version. `rooms/v6.md` says v3–v5 events
  "might not be fully compliant", so one float in a v3–v5 room blocks everything that
  descends from it.
- `StateKeyHash` combines unseeded `std::hash` values with XOR. It is bounded by the
  10 000-key cap.

### Area 5 — coverage gaps

- Not read closely: `canonicaljson/value.cpp`, and the yyjson handling of lone `\u`
  surrogates.
- Spec sections "Checks performed on receipt of a PDU" and "Soft failure" were compared
  only as far as the callers audited in Area 4.

---

## Area 6 — Outbound requests and SSRF

**Result:** 8 findings confirmed: 1 high, 3 medium, 4 low. Two of them came from the
verifier. The verifier corrected the mechanism of OUT-1, reproducing libcurl's and
glibc's handling in an isolated scratch environment.

**Prior fixes and controls that hold:**
- M-06: the literal-discovery opt-in has no production caller.
- Redirects are refused (`FOLLOWLOCATION=0`).
- Outbound requests use https only.
- Header and body caps.
- The push gateway URL, path and `enabled` gates.
- The identity-server allowlist: clients cannot supply an arbitrary base URL.
- `/preview_url` is not implemented, so it is no SSRF surface.

### OUT-7 — `security.media.remote_fetch_enabled=false` does not stop remote media fetches

- **Severity:** high
- **Attacker:** A1
- **Verdict:** found by the verifier; confirmed by the orchestrator. The verifier rated
  it medium and the orchestrator raised it (see Impact).
- **Location:**
  - `src/homeserver/media_service.cpp:705-746` (`fetch_remote_media_live`), `:1008-1023`,
    `:1063`
  - `src/media/repository.cpp:807`, `:827`
  - `include/merovingian/config/config.hpp:422`
- **Rule:** `docs/user-manual.md:899` describes the flag as the "Opt-in for live remote
  media fetching". It defaults to off.
- **Path:**
  1. `GET /_matrix/media/v3/download/{server}/{id}` is served before authentication.
  2. It reaches `fetch_remote_media_live`. That function runs server discovery, the
     federation media request (up to `max_upload_bytes + 4096`, 120 s total) and the
     legacy fallback.
  3. The flag is checked only in `media::fetch_remote_media`, after the bytes have
     arrived, and the result is then discarded.
  4. Nothing under `src/homeserver/` reads the flag.
- **Impact:**
  - On the default configuration, any unauthenticated caller can make the server
    connect to an arbitrary server and download up to about 50 MiB.
  - Each request holds a main-pool worker for up to about 150 s, so 8 such requests
    stall the server (compare HTTP-1).
  - It makes OUT-1 and OUT-2 reachable on the default configuration.
- **Fix:**
  - Check the flag at the top of `fetch_remote_media_live` and in the thumbnail path,
    before any discovery.
  - Run remote fetches outside the main pool, with an in-flight cap.
- **Test:** GIVEN `remote_fetch_enabled=false` WHEN an unauthenticated client requests
  `/_matrix/media/v3/download/remote.example/abc` THEN no discovery or outbound call
  occurs and the response is 404.

### OUT-1 — Server names containing `@`, `?` or `#` defeat address pinning

- **Severity:** medium · **Attacker:** A1 · **Verdict:** adjusted (mechanism corrected)
- **Location:**
  - `src/federation/security.cpp:121-125` (weak `server_name_is_valid`)
  - `src/federation/server_discovery.cpp:294-304`, `:530-649`
  - `src/http/outbound_client.cpp:187-223`, `:410-442`, `:713-729`
  - `src/federation/outbound_transaction.cpp:45-63`
  - `src/federation/remote_key_cache.cpp:213-226`
- **Spec:** `appendices.md` Server Name: `dns-char = DIGIT / ALPHA / "-" / "."`.
- **Project rule:** `src/http/AGENTS.md` says pinning through `CURLOPT_RESOLVE` keeps the
  SSRF policy "the single source of truth".
- **Path:**
  1. Three entry points accept such a name, all before authentication:
     - the X-Matrix `origin="x@evil.example"` header, which triggers key resolution
       before the signature is checked;
     - `GET /directory/room/%23a%3Ax%40evil.example`;
     - the media download path (with OUT-7).
  2. `federation::server_name_is_valid` accepts `@ ? # \ %`. The strict
     `auth::server_name_is_valid` (`src/auth/identity.cpp:252`) is not used here.
  3. glibc `getaddrinfo` refuses these names, so the direct and `.well-known` steps fail.
     `res_query` does send `_matrix-fed._tcp.x@evil.example`, so SRV is the working
     vector.
  4. The attacker's DNS answers SRV with a public target and port P. Only that target
     is SSRF-checked and pinned.
  5. The URL becomes `https://x@evil.example:P/…`, and the pin key is
     `x@evil.example:P`.
  6. libcurl treats `x` as userinfo and `evil.example` as the host, so the pin never
     matches. curl then resolves the name through system DNS, which the attacker answers
     with an internal address.
  7. No connect-time check exists: there is no `OPENSOCKETFUNCTION`, and seccomp permits
     `connect`.
- **Impact:**
  - A pre-authentication blind TCP connect plus a TLS ClientHello to an
    attacker-chosen internal host and port.
  - The TLS name check fails, so no data comes back. It still works as an internal
    port-scan and timing oracle.
  - Cloud metadata endpoints are plain HTTP and cannot be reached.
- **Fix:**
  - Apply the strict server-name grammar at every entry point and in `discover_server`.
  - In `OutboundClient`, derive the pin host and port with libcurl's URL API (CURLU),
    and refuse any authority containing `@ ? # \`.
  - Add a connect-time address check (`CURLOPT_OPENSOCKETFUNCTION`) as defence in depth.
- **Test:**
  - GIVEN an `OutboundRequest` to `https://x@example.org/p` WHEN it is performed THEN it
    returns `invalid_url` and no socket opens.
  - GIVEN X-Matrix `origin="a@b.example"` THEN no discovery occurs.

### OUT-2 — A remote media redirect's `Location` is validated by one parser and connected by another

- **Severity:** medium · **Attacker:** A7 (reachable on the default configuration through
  OUT-7) · **Verdict:** confirmed
- **Location:** `src/homeserver/media_service.cpp:153-208`, `:660-668`, `:924-944`;
  `src/http/outbound_client.cpp:197-198`
- **Path:**
  1. `parse_https_authority` stops at `/`, `?` or `#`, and SSRF-checks and pins the host
     it finds.
  2. The raw `Location` is then passed to `OutboundClient`, whose parser stops only at
     `/`.
  3. For `https://rebind.example#x`, the pin key never matches, and curl re-resolves the
     host. That DNS-rebinding window reaches internal addresses on port 443.
- **Fix:** parse once, then build the request from the parsed parts; OUT-1's
  `OutboundClient` fix also closes this.
- **Test:** GIVEN a redirect to `https://a.example#x` whose second lookup returns
  127.0.0.1 WHEN the fetch runs THEN no connection reaches 127.0.0.1.

### OUT-4 — Remote media is re-fetched and stored on every request, with no cache and no eviction

- **Severity:** medium (when `remote_fetch_enabled=true`) · **Attacker:** A1 · **Verdict:**
  confirmed
- **Location:** `src/homeserver/media_service.cpp:479`, `:1017-1023`;
  `src/media/repository.cpp:289-302`, `:540-560`;
  `include/merovingian/config/config.hpp:396-404`
- **Detail:**
  - There is no lookup by (origin, mediaId), so each request fetches again and appends a
    record.
  - The default quotas are unlimited, so memory grows until the process runs out.
  - With quotas configured, remote media fills them and local uploads are refused with
    507.
- **Fix:**
  - Give remote media its own cache keyed by (origin, mediaId), with LRU or TTL eviction
    and a budget separate from local uploads.
  - Rate-limit remote fetches per client and per origin.
- **Test:** GIVEN remote fetch enabled WHEN the same remote media is requested 1000 times
  THEN at most one record exists and the origin sees one fetch within the TTL.

### OUT-3 — One user's stalled push gateways consume the global push-delivery cap

- **Severity:** low (push is off by default; drop-at-cap is documented in ADR-0028 and
  ADR-0029) · **Attacker:** A2 · **Verdict:** adjusted from medium
- **Location:** `src/homeserver/room_service.cpp:5621-5636`, `:5716-5779`;
  `src/homeserver/client_server.cpp:10910-10960`
- **Detail:**
  - The number of pushers a user can register is uncapped.
  - Each delivery calls up to 10 pushers in sequence, each with a 30 s timeout.
  - 128 such tasks exhaust the global cap, after which every user's pushes are dropped.
- **Fix:**
  - Give each user an in-flight cap.
  - Break the circuit to a stalled gateway host.
  - Cap the number of pushers per user.
- **Test:** GIVEN one user with 10 stalled gateways WHEN another user's event is sent THEN
  that delivery is still dispatched.

### OUT-5 — libcurl honours proxy environment variables, which bypass pinning

- **Severity:** low (needs control of the operator's environment) · **Verdict:** confirmed
- **Location:** `src/http/outbound_client.cpp:410-442`
- **Fix:** set `CURLOPT_PROXY=""` and `CURLOPT_NOPROXY="*"` explicitly, and fail closed if
  either cannot be set.
- **Test:** GIVEN `https_proxy` pointing at a local listener WHEN a pinned request runs
  THEN the listener receives no connection.

### OUT-6 — The server-discovery cache is unbounded

- **Severity:** low · **Attacker:** A1 · **Verdict:** confirmed
- **Location:** `src/federation/cached_server_discovery.cpp:24-50`
- **Fix:** cap the cache size, sweep expired entries, and never cache names that fail
  the strict grammar.
- **Test:** GIVEN a cap of N WHEN N+1 names are discovered THEN at most N remain.

### OUT-8 — `security.federation.deny_ip_ranges` is validated but never applied

- **Severity:** low (the documentation over-promises) · **Verdict:** found by the
  verifier, confirmed by the orchestrator
- **Location:** `src/config/config.cpp:962-969`; `src/federation/runtime_federation.cpp:64`;
  `src/federation/security.cpp:40-160` (hard-coded ranges); `docs/threat-model.md:723`,
  `:786`
- **Fix:** apply the configured ranges in `address_set_allowed`, or remove the setting
  and correct the threat model.
- **Test:** GIVEN `deny_ip_ranges` containing 203.0.113.0/24 WHEN a destination resolves
  into it THEN discovery is refused.

### Area 6 — hardening notes

- **Ranges the built-in deny list does not block:**
  - IPv4: 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24 and
    192.88.99.0/24.
  - IPv6: `::/96`, `fec0::/10`, `2002::/16` (6to4 with an embedded private address),
    Teredo `2001::/32` and `64:ff9b:1::/48`.
  - Treat IPv4-embedded IPv6 forms by their embedded address.
- An IPv6-literal server name cannot federate, because `parse_request_host_port` splits
  at the first `:`.
- Inbound requests from servers delegated to port 8008 are refused
  (`server_discovery.cpp:204`).
- `.well-known` redirects are refused, and the cache TTL is a fixed 60 s. The spec says
  redirects "should be followed" and recommends a 24 h TTL.
- `allow_remote=false` is ignored on client download and thumbnail requests.
- The `get_missing_events` outbound path does not percent-encode `room_id`
  (`local_http_router.cpp:2680`).

### Area 6 — coverage gaps

- Read only in part: the worker IPC path for outbound requests, and `dispatch_worker.cpp`
  retry logic.
- Not verified: resolver behaviour on the BSDs for names containing `@`. The direct-path
  variant of OUT-1 may also work there.

---

## Area 7 — Cryptography, key management and worker IPC

**Result:** 6 findings confirmed: 1 high, 1 medium, 4 low. Refuted: half of CRY-5, and
the claim that `sodium_init` is unchecked.

**What holds:**
- The IPC handshake and framing. The authentication MAC binds a role byte and both
  ephemeral public keys, and is verified before key derivation.
- Keys are separated per direction with `crypto_kx`. Secretstream provides ordering and
  replay protection, and accepts `TAG_MESSAGE` only.
- The IPC socket is a `socketpair` passed with `CLOEXEC`.
- No non-CSPRNG randomness is used anywhere.
- `sodium_init` is called lazily and checked, failing closed, on every use.
- Prior fixes L-07, M-07, H-05, and the 0.12.5 findings 1, 2, 3, 5, 20 and 21, still
  hold.
- N1 (the worker holds no master-key file) and #419, #432 and #433 still hold.

### CRY-1 — The main process signs arbitrary bytes with any held key when the federation worker asks

- **Severity:** high · **Attacker:** A5 · **Verdict:** confirmed (orchestrator re-checked the
  handler)
- **Location:**
  - `src/homeserver/worker_pool.cpp:1242-1262`
  - `src/crypto/runtime_multikey_ed25519_provider.cpp:24-41`
  - `src/ipc/ipc_ed25519_provider.cpp:111-125`
  - `src/federation_worker/worker_event_loop.cpp:599`, `:607`
- **Rule:**
  - `src/federation_worker/AGENTS.md` rule 1.
  - ADR-0015: "A compromised worker can request signatures but cannot exfiltrate the
    signing key. That is the entire point of the split".
  - `docs/threat-model.md:372-379` presents the split as the fix for "a compromised worker
    could forge federation signatures".
- **Path:**
  1. A compromised worker sends
     `{"type":"sign_request","key_id":"ed25519:…","canonical_json":"<any bytes>"}`.
  2. Main's handler signs whatever it is given with whichever held key is named,
     including retired keys. There is no domain tag, no allowlist of request shapes, no
     key pinning and no binding to an operation main started. The only limit is the
     per-channel in-flight cap of 256.
  3. The handler also holds the global `runtime_.mutex` while it signs. Frames can be
     about 87 MiB (see CRY-2), so it doubles as a lock-hold DoS.
- **Production need:** none.
  - Outbound X-Matrix requests are signed in main (`room_service.cpp:1725-1746`: "the
    Ed25519 secret never crosses the IPC boundary"), and so are invites.
  - `/_matrix/key/v2/server` is served by main.
  - The worker installs the IPC provider only so that it can skip loading the key
    (`runtime.cpp:729-733`).
- **Impact:**
  - A compromised worker, the process that is most exposed, can mint valid signatures
    as this server: forged PDUs "from" any local user, forged X-Matrix requests, and
    forged key responses.
  - It still has outbound network access, so it can deliver them to any peer.
  - ADR-0071's re-verification does not help, because the forgeries go to third parties,
    not through main.
  - The documentation understates this. The oracle appears once, as an ADR-0015
    consequence, and rests on a "must produce signatures" premise the code contradicts.
- **Fix:**
  - Remove the `sign_request` frame, `IpcEd25519Provider` and the worker's
    `signing_override`, and give the worker a provider that refuses every request.
  - If worker-originated signing is ever needed, accept only typed requests. Main then
    builds the payload itself from validated fields, pins the active key, and refuses
    anything shaped like an event.
  - Correct ADR-0015 with a superseding ADR, and correct the threat model.
- **Test:** GIVEN a connected worker channel WHEN it sends `sign_request` containing a
  serialised PDU or arbitrary bytes THEN the response is an error with no signature AND
  the runtime lock is not taken.

### CRY-2 — A compromised worker can exhaust main's memory through the IPC dispatch queue

- **Severity:** medium · **Attacker:** A5 · **Verdict:** confirmed
- **Location:**
  - `src/ipc/channel.cpp:57-65`, `:157-171`, `:228-231`, `:397-490`
  - `include/merovingian/ipc/channel.hpp:211`
  - `src/homeserver/worker_pool.cpp:436-450`, `:1119-1126`
- **Rule:** ADR-0065 says a flooding worker "can only occupy `ipc_max_in_flight_requests`
  slots per channel, capping memory regardless of how fast it sends frames". That is not
  true of the queue.
- **Path:**
  1. The reader thread decrypts and parses each frame, then appends it to an unbounded
     `std::deque`.
  2. The in-flight cap applies only after a frame is dequeued.
  3. The per-frame cap is sized for main-to-worker `send_join` responses (about 87 MiB at
     the default `join_response_max_size`), but it is applied in both directions.
  4. `raw_send_exact` blocks, with no send timeout. A worker that stops reading
     therefore stalls the dispatcher and handler threads while the reader keeps queueing.
     `handler_pool_` is shared across shards.
- **Impact:**
  - The sandboxed process can OOM-kill the process it is sandboxed from.
  - Even without the queue, 256 in-flight frames of 87 MiB allow about 22 GiB to be
    retained.
- **Fix:**
  - Bound the queue by count and by bytes, and apply backpressure or mark the channel
    unhealthy when it is full.
  - Add a send timeout.
  - Use a small frame cap for worker-to-main requests.
  - Make the in-flight cap byte-aware.
- **Test:** GIVEN a peer that sends maximum-size frames and never reads WHEN the queue
  reaches its cap THEN the channel is marked unhealthy or reading stops, and resident
  memory stays bounded.

### CRY-3 — The master key's length is not enforced

- **Severity:** low (needs both a low-entropy key from the operator and a database leak) ·
  **Verdict:** adjusted from medium
- **Location:** `src/crypto/master_key.cpp:31-100`; `src/crypto/secret_box.cpp:67-82`;
  `src/crypto/token_key.cpp:72-88`; `src/crypto/ipc_auth_key.cpp:67-82`;
  `tests/unit/test_crypto.cpp:816-834`
- **Detail:**
  - Any length from 1 to 4096 bytes is accepted. The existing test accepts 24 bytes.
  - `docs/user-manual.md:614` and `:2139` describe a 32-byte key.
  - Subkeys are a single BLAKE2b keyed by a public label, with no stretching. A
    passphrase-style key therefore lets someone holding the database brute-force the
    encrypted signing secret offline.
- **Fix:**
  - Require at least 32 bytes and refuse an all-zero file.
  - Derive subkeys with `crypto_kdf_derive_from_key`.
  - Update the test.
- **Test:** GIVEN a master-key file of 24 bytes WHEN the server starts THEN startup is
  refused with a message naming the 32-byte minimum.

### CRY-4 — `SecretBuffer` page locking is unreliable, and derived keys are not locked

- **Severity:** low · **Attacker:** A6 (swap or raw memory) · **Verdict:** confirmed
- **Location:**
  - `src/core/secret_buffer.cpp:19-42`, `:76-95`
  - `src/crypto/master_key.cpp:53`, `:85`, `:138-141`
  - `src/homeserver/auth_service.cpp:121-149`
- **Detail:**
  - The backing store is a `std::vector` on the ordinary heap, locked with
    `sodium_mlock`.
  - `munlock` is page-granular and not reference-counted. Destroying one buffer, such as
    the 4096-byte scratch buffer in `load_master_key_material`, therefore unlocks
    neighbouring secrets on the same page, while their `is_locked()` still reports
    true.
  - The secret-box, token-HMAC and IPC-auth keys live in plain `std::array` caches.
  - `sodium_malloc` is not used anywhere.
- **Fix:** back `SecretBuffer` and the derived-key caches with `sodium_malloc`.
- **Test:** GIVEN two live `SecretBuffer`s on one page WHEN one is destroyed THEN the other
  stays locked.

### CRY-5 — Registration validation secrets are compared with `!=`

- **Severity:** low (a project-rule violation; not practically exploitable) ·
  **Verdict:** adjusted. The `mutual_rooms` half is refuted: the compared value only
  selects an offset the caller could reach by paging.
- **Location:** `src/homeserver/client_server.cpp:1814`, `:1840`
- **Rule:** `docs/security-coding-rules.md:205`: "Always use constant-time comparison for
  secrets".
- **Fix:** use `crypto::constant_time_equal` (hash, then compare), or key sessions by a
  hash of `client_secret`.
- **Test:** GIVEN a session WHEN a `client_secret` is presented THEN it is compared with
  the constant-time helper.

### CRY-6 — Token issuance falls back to an unkeyed hash if the master key becomes unavailable

- **Severity:** low · **Verdict:** confirmed (hardening)
- **Location:** `src/homeserver/auth_service.cpp:244-277`;
  `docs/crypto-boundary.md:218-220`
- **Detail:**
  - When the key derivation fails at runtime, for example because the key file was
    replaced or has become unreadable, newly issued tokens are silently hashed without a
    key.
  - `docs/crypto-boundary.md` still describes a no-master-key mode, which no longer
    exists since 0.12.5.
- **Fix:** fail issuance with 503 instead, and correct the document.
- **Test:** GIVEN the master key becomes unreadable after start WHEN a token is issued
  THEN issuance fails and no unkeyed digest is stored.

### Area 7 — hardening notes

- The mutual-rooms pagination key is derived from the Ed25519 signing secret
  (`runtime.cpp:773-784`), which crosses key purposes. Its MAC input also concatenates
  fields with no separator (`client_server.cpp:3216-3220`).
- Retired signing-key secrets stay in the database indefinitely.
- A channel that becomes unhealthy while its worker process stays alive is never
  respawned, so that shard answers 503 until the worker exits.

### Area 7 — coverage gaps

- Not audited: the frame serialisers in `federation_ipc_frames.cpp`, and TLS private-key
  handling.
- The thumbnail-worker pipe framing was skimmed only; see Area 9.

---

## Area 8 — Process isolation and platform hardening

**Result:** 8 findings confirmed: 1 high, 2 medium, 5 low. Four were adjusted downward.
The verifier demonstrated the kernel semantics behind ISO-1 with a scratch program on
this host.

**Prior fixes that hold:**
- #319 (no `execve` in the worker profile) and #428.
- ADR-0042 (minimal worker environment).
- 0.12.5 findings 21 and 22.
- ADR-0062 parts 1–3 as written.
- ADR-0071.
- The M-08 decoder profile.
- The BPF architecture guard, which also defeats the x32 bypass.
- `KILL_PROCESS` as the default seccomp action.
- No `ptrace`, `bpf`, `userfaultfd`, `keyctl`, `mount` or `unshare` in any allowlist.

The thumbnail decoder is not affected by ISO-1: it creates no threads and installs its
filter first.

### ISO-1 — The worker's seccomp and Landlock sandbox does not cover the logger threads, which start before it is applied

- **Severity:** high (federation worker); low (main process, whose own filter allows
  `execve`)
- **Attacker:** A5
- **Verdict:** confirmed; re-checked by the orchestrator and demonstrated by the verifier
- **Location:**
  - `include/merovingian/observability/logger.hpp:178-182`, `:334-338`
  - `src/federation_worker/main.cpp:134`, `:183`, `:213`
  - `src/platform/seccomp_hardening.cpp:790`, `:818`, `:829-853`
  - `src/platform/landlock_hardening.cpp:273-286`
- **Rule:**
  - `src/platform/AGENTS.md` rule 1.
  - ADR-0062 part 3: "A compromised worker … can no longer open any of those directly
    off disk".
  - The code comments say hardening runs "before … starts threads" (`main.cpp:205-206`,
    `runtime_hardening.cpp:596`).
- **Path:**
  1. The worker's first `LOG_INFO` (`main.cpp:134`) constructs `SingleLog`. Its
     constructor always starts two writer threads.
  2. Landlock (`:183`) and the worker seccomp filter (`:213`) are then installed with
     flags 0. Both apply to the calling thread only; no `SECCOMP_FILTER_FLAG_TSYNC` is
     used anywhere in the repository.
  3. The two logger threads therefore keep only the filter inherited from main, which
     allows `execve`, `open`, `socket` and `connect`. They have no Landlock ruleset and
     no worker filter.
  4. With code execution in any worker thread, the attacker installs a signal handler
     (`rt_sigaction` is allowed) and aims it at a logger thread with `tgkill` (also
     allowed).
  5. The handler then runs unconfined. It can read the master key, the database URI
     file and TLS keys, or `execve` a shell.
  6. The self-check reads `/proc/self/status`, which reports the thread-group leader
     only, so it cannot see this.
  7. No test covers multi-threaded enforcement.
- **Impact:**
  - The federation worker's documented containment can be bypassed with syscalls its own
    allowlist permits.
  - Stealing the master key and the database's encrypted signing secret yields the
    server's signing key.
- **Fix:**
  - Make sure no thread exists before hardening: start the logger's writers lazily or
    explicitly, and move the worker's first log line after seccomp.
  - Install seccomp with `SECCOMP_FILTER_FLAG_TSYNC`, and treat failure as fatal.
  - Landlock has no equivalent on older kernels, so the ordering is what matters there.
  - Extend the self-check to every `/proc/self/task/<tid>/status`.
- **Test:** GIVEN a process that has already logged WHEN the worker hardening sequence is
  applied THEN every task reports `Seccomp: 2` and `NoNewPrivs: 1` AND a pre-existing
  thread cannot `execve` or open the master-key path.

### ISO-2 — A compromised worker can kill, freeze or resource-starve the main process

- **Severity:** medium · **Attacker:** A5 · **Verdict:** confirmed
- **Location:**
  - `src/platform/seccomp_hardening.cpp:589-591`, `:620`
  - `src/homeserver/worker_supervisor.cpp:425`
  - `include/merovingian/platform/landlock_hardening.hpp:133`
- **Detail:**
  - `kill`, `tkill`, `tgkill` and `prlimit64` are allowed with no argument filtering.
  - The worker runs as the same uid as main.
  - Landlock is capped at ABI 3, so signal scoping (ABI 6) is never used.
  - `kill(getppid(), SIGSTOP)` freezes main without a crash, so systemd's
    `Restart=on-failure` never fires.
  - `prlimit64` can lower main's `RLIMIT_NOFILE` or `RLIMIT_AS`.
  - `docs/threat-model.md` does not mention this path.
- **Fix:**
  - Run the worker under a distinct uid.
  - Otherwise, argument-filter these syscalls to the worker's own process, remove `kill`
    and `tkill`, and use `LANDLOCK_SCOPE_SIGNAL` on ABI 6 and later.
- **Test:** GIVEN the worker filter WHEN it calls `kill(getppid(), 0)` or
  `prlimit64(getppid(), …)` THEN the call is denied.

### ISO-3 — The worker supervisor stops respawning after a single failed restart

- **Severity:** medium (availability) · **Attacker:** A3 can induce the crash; the spawn
  failure is environmental · **Verdict:** confirmed
- **Location:** `src/homeserver/worker_supervisor.cpp:461-543`
- **Path:**
  1. After a crash, `worker_pid_` is set to -1.
  2. If `spawn_and_connect` then throws (`EAGAIN`, `ENOMEM`, `EMFILE`, or the binary is
     missing during an upgrade), the exception is only logged.
  3. The next loop iteration calls `waitpid(-1, WNOHANG)`. Depending on what else is
     running, that:
     - exits the supervisor thread on `ECHILD`, permanently;
     - returns 0 forever, so no respawn is ever attempted; or
     - reaps a sibling shard's child, whose own supervisor then exits.
- **Impact:** a shard stays at 503 until the server restarts. `docs/threat-model.md:469`
  promises automatic restarts with exponential back-off.
- **Fix:**
  - Never call `waitpid(-1)`.
  - Treat `worker_pid_ <= 0` as "spawn needed" and retry with back-off.
  - Reset the back-off only after a minimum uptime.
- **Test:**
  - GIVEN a worker exits and the next spawn fails once WHEN the condition clears THEN the
    supervisor respawns AND `healthy()` becomes true.
  - GIVEN two shards WHEN shard A's respawn fails THEN shard B's child is not reaped.

### ISO-4 — On SQLite the worker can write to main's database

- **Severity:** low (SQLite is documented for small installations) · **Attacker:** A5 ·
  **Verdict:** adjusted from medium
- **Location:** `src/database/sqlite_store.cpp:148`;
  `src/platform/landlock_hardening.cpp:329-330`; `docs/threat-model.md:429-442`
- **Detail:**
  - Directory read-write access is documented as necessary for WAL.
  - The residual-risk text says only "readable". A compromised worker can also change
    main's system of record, for example admin flags or room state.
- **Fix:** correct the wording. Better, require PostgreSQL when the worker is enabled, or
  open the database `SQLITE_OPEN_READONLY` with a separate `-shm` grant.
- **Test:** GIVEN SQLite and the worker under Landlock WHEN it opens the database for
  writing THEN the open fails.

### ISO-5 — The thumbnail decoder inherits main's environment and stderr, and its output is not checked

- **Severity:** low · **Verdict:** adjusted
- **Location:** `src/media/thumbnailer.cpp:462`, `:527-532`;
  `src/core/file_descriptor.cpp:222-224`
- **Fix:**
  - Use the minimal worker environment.
  - Point fd 2 at `/dev/null`.
  - Validate the PNG signature and IHDR dimensions in the parent.
- **Test:** GIVEN a decoder response that is not a PNG matching the reported size WHEN
  main processes it THEN it returns 502.

### ISO-6 — No umask is set, and the registration token is written before it is `chmod`ed

- **Severity:** low · **Attacker:** A6 · **Verdict:** adjusted
- **Location:**
  - `src/database/sqlite_store.cpp:139-148`
  - `include/merovingian/observability/logger.hpp:270` (the log file follows symlinks
    and is not `O_CLOEXEC`)
  - `packaging/deb/postinst:16-21`
  - `packaging/systemd/merovingian.service`
- **Detail:** the packaged `0750` directories mask this. Unpackaged installs get `0755`
  and `0644` files.
- **Fix:**
  - Call `umask(0077)` early in each executable, and set `UMask=0077` in the unit.
  - Create the database and log file with `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode
    0600.
  - In the package scripts, write the token under `umask 077`.
- **Test:** GIVEN a fresh `sqlite_path` in a new directory WHEN the store opens THEN the
  file is 0600 and the directory is 0700.

### ISO-7 — Secret files are checked with `lstat` and then opened again by path, with no owner check

- **Severity:** low · **Attacker:** A6 (only with a misconfigured directory) ·
  **Verdict:** adjusted
- **Location:** `src/platform/file_metadata.cpp:56`, `:81-93`; `src/main.cpp:196-211`;
  `src/crypto/master_key.cpp:37-40`; `src/homeserver/worker_pool.cpp:1016`
- **Fix:** use the pattern `auth_service.cpp:563` already uses: `open(O_NOFOLLOW|O_CLOEXEC)`,
  then `fstat`, then require `st_uid == geteuid()` and mode 0400, then read from the same
  descriptor.
- **Test:** GIVEN a secret path that is a symlink, or a file owned by another uid WHEN it
  is loaded THEN loading fails.

### ISO-8 — The systemd unit omits address-family, umask and kernel-protection directives, and the worker may open any socket family

- **Severity:** low · **Verdict:** confirmed
- **Location:** `packaging/systemd/merovingian.service`;
  `src/platform/seccomp_hardening.cpp:491`
- **Fix:**
  - Add `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `UMask=0077`,
    `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`,
    `ProtectControlGroups=` and `RestrictNamespaces=`.
  - Argument-filter `socket()` domains in the worker profile.
  - Document that the worker's PostgreSQL role must use password authentication, not
    peer authentication, because Landlock does not govern AF_UNIX `connect`.
- **Test:** GIVEN the worker filter WHEN it calls `socket(AF_ALG, …)` THEN it is killed.

### Area 8 — hardening notes

- `posix_spawn` of the federation worker does not use `closefrom`, and relies on every
  descriptor being `CLOEXEC`. The log `ofstream` is not `CLOEXEC`.
- The restart back-off resets to 1 s immediately after a successful spawn, so it never
  grows for a crash loop.
- `ioctl` and `fcntl` are unrestricted in both profiles. `PR_SET_MDWE` is not used, so
  outside systemd there is no W^X enforcement.
- `apply_linux_capability_bounding_set` returns success even if every
  `PR_CAPBSET_DROP` fails (`runtime_hardening.cpp:405-409`).

### Area 8 — coverage gaps

- Not examined: `src/platform/elf_probe.cpp`, BSD pledge and Capsicum behaviour beyond a
  static read, and the OpenRC and BSD `rc.d` scripts.

---

## Area 9 — Media repository and thumbnailer

**Result:** 8 findings confirmed: 5 medium, 3 low. The verifier also re-found OUT-7,
independently.

**Design facts that remove whole attack classes:**
- Blobs live in memory and in the database, not on the filesystem, so path traversal
  and filename collisions do not apply.
- The stored `Content-Type` is always the server-sniffed type, from png, jpeg, gif, pdf,
  text/plain or octet-stream. Stored SVG or HTML XSS is therefore not reachable.
- Media IDs are 128-bit random values from the CSPRNG.
- The federation multipart boundary is random.
- The decoder uses libpng's simplified API and turbojpeg, with no C++ frames between a
  `setjmp` and its `longjmp`.

**Prior fixes that hold:**
- 0.12.5 #8.
- M05 random IDs.
- M-09 / #448.
- #443/#444 (media ID shapes).
- #445 (markup sniffed as text).
- #449, for the target size.
- #418.
- The 0.12.13 decoder hardening.

**Regressed:** the M05 legacy freeze (MED-1).

### MED-1 — The freeze on legacy unauthenticated media downloads is lost on every restart

- **Severity:** medium (upper end) · **Attacker:** A1 holding an mxc URI · **Verdict:**
  confirmed and re-checked by the orchestrator; adjusted from high because the spec says
  SHOULD
- **Location:**
  - `src/homeserver/runtime.cpp:124-153` (`hydrate_media_repository`)
  - `include/merovingian/media/repository.hpp:59` (default `true`)
  - `src/media/repository.cpp:637`, `src/homeserver/media_service.cpp:1084`
- **Spec:** "servers SHOULD "freeze" the deprecated, unauthenticated, endpoints to prevent
  newly-uploaded media from being downloaded … any media uploaded *after* (or *during*)
  the freeze SHOULD only be accessible through the new, authenticated, endpoints."
- **Rule:** ADR-0068 ("the freeze survives any backup/restore"),
  `docs/media-repository.md:135`, `docs/database-persistence.md:618`.
- **Path:**
  1. An upload stores `legacy_endpoint_visible=false`, and the loaders read it back.
  2. Hydration never copies the flag, so after a restart every record has the struct
     default `true`.
  3. `GET /_matrix/media/v3/download|thumbnail/…` is served before authentication and
     passes the check.
- **Impact:** after any restart, all media uploaded since the upgrade can be downloaded
  without a token. No test covers restart.
- **Fix:**
  - Copy the flag in hydration.
  - Make the struct default `false`, failing closed.
  - Add a restart test.
- **Test:** GIVEN a post-upgrade upload WHEN the runtime restarts from the same database
  THEN `GET /_matrix/media/v3/download/{s}/{id}` returns 404 AND the v1 authenticated
  route returns 200.

### MED-2 — Quarantined remote media is served anyway, and its bytes leak into error bodies

- **Severity:** medium · **Attacker:** A1 or A2 requesting; A3 or A7 supplying the content
  · **Verdict:** confirmed
- **Location:**
  - `src/media/repository.cpp:586-616`, `:865-880`
  - `src/homeserver/media_service.cpp:501-505`, `:1055-1074`
  - `src/homeserver/local_http_router.cpp:422-425`
  - `src/homeserver/client_server.cpp:7550-7554`
- **Rule:** the default `remote_fetch_media_policy` is `quarantine`, meaning "held for
  admin review" (`config.hpp:415-419`).
- **Path:**
  1. A quarantined upload returns `ok=true` with status 202.
  2. Remote fetch passes that on with the bytes. Nothing checks the `quarantined` flag.
  3. Thumbnail requests accept any 2xx, so they decode the held image and serve a 200
     thumbnail.
  4. Download requests turn the 202 into `dispatch_err(202, "M_UNKNOWN", "<ct>|<raw
     bytes>")`. The held content is embedded in the JSON error body, and remote
     downloads are broken on the default policy.
- **Fix:**
  - Carry `quarantined` through the remote-fetch result and refuse to return bytes when it
    is set.
  - Never put payload bytes in an error string.
  - Require exactly 200 in the thumbnail path.
- **Test:** GIVEN the quarantine policy and a remote serving a valid PNG WHEN v1 download
  and v1 thumbnail are requested THEN neither response contains image bytes or a 2xx
  status.

### MED-3 — Re-uploading content an admin removed corrupts its database row, and a later removal does not erase it

- **Severity:** medium (integrity; moderation) · **Attacker:** A2 · **Verdict:** confirmed
- **Location:**
  - `src/media/repository.cpp:60-66`, `:386-392`, `:522-535`, `:763-795`
  - `src/homeserver/media_service.cpp:49-62`, `:1093`
  - `src/database/persistent_store.cpp:2690`
- **Path:**
  1. Removal leaves a dead blob (ref 0, bytes cleared).
  2. A re-upload of the same bytes appends a second blob with the same `storage_id`.
  3. `find_local_media_blob` returns the first match, which is the dead blob.
  4. Persistence then upserts the dead blob over the database row, so the live bytes are
     never stored. After a restart the re-upload returns 500.
  5. Thumbnails fail immediately.
  6. A later admin removal decrements the dead blob, so the live copy is never erased from
     memory or the database.
- **Fix:**
  - Keep one blob per `storage_id`, reviving or reusing the dead one.
  - Make every lookup consider only live blobs.
- **Test:** GIVEN media removed and then re-uploaded WHEN the runtime restarts THEN it
  downloads intact AND WHEN the re-upload is removed THEN its bytes are cleared in memory
  and in the database.

### MED-5 — `allow_remote` is ignored and server names are compared exactly, so the server can fetch from itself

- **Severity:** medium · **Attacker:** A1 (reachable on the default configuration through
  OUT-7) · **Verdict:** confirmed; whether the loop actually forms is rated likely ·
  **Status:** fixed in 0.12.19
- **Location:** `src/homeserver/media_service.cpp:770-783`, `:1017`, `:1055`;
  `src/homeserver/local_http_router.cpp:1109-1135`
- **Spec:** "`allow_remote` … Indicates to the server that it should not attempt to fetch
  the media if it is deemed remote. This is to prevent routing loops where the server
  contacts itself."
- **Path:**
  1. A request for `/_matrix/media/v3/download/EXAMPLE.com/<id>`, or
     `example.com:8448`, is treated as remote.
  2. Discovery resolves to this server, which fetches from itself.
  3. The fallback carries `?allow_remote=false`, but the parameter is never read inbound,
     so the chain can repeat. Each hop holds a worker for up to 120 s.
- **Fix:**
  - Honour `allow_remote=false` on inbound download and thumbnail requests.
  - Canonicalise server names (lowercase, default port) before comparing.
  - Reject discovery results that resolve to this server's own listener.
- **Test:** GIVEN `?allow_remote=false` or a case variant of the local name WHEN media is
  requested THEN no outbound request is made and the response is 404.

### MED-6 — Media quotas default to unlimited, and blobs are held twice in memory

- **Severity:** medium (a documented default, but its consequence is not) · **Attacker:** A2
  · **Verdict:** confirmed
- **Location:**
  - `include/merovingian/config/config.hpp:396-406`
  - `src/homeserver/runtime.cpp:145-149`
  - `src/database/persistent_store.cpp:2718-2727`
  - `src/media/repository.cpp:60-83`
- **Detail:**
  - `max_total_size`, `max_size_per_user` and `max_records` all default to no limit.
    0.12.5 finding 19 was fixed as opt-in only.
  - Every blob is held in `repository.blobs` and again in `store.media_blobs`.
  - One account can store about 1 GB a minute per IP (50 MiB × 20 per minute), which is
    about 2 GB of RAM.
- **Fix:**
  - Ship non-zero default caps.
  - Stop keeping blob bytes in the persistent-store mirror.
  - Index records and blobs.
- **Test:** GIVEN the default configuration WHEN one user exceeds the default per-user
  quota THEN the upload gets 507.

### MED-4 — Thumbnail generation runs under the global runtime mutex

- **Severity:** low · **Attacker:** A2, or A1 through MED-1 · **Verdict:** adjusted from
  medium (decoding is bounded by the 4.1-megapixel cap and the media rate tier)
- **Location:** `src/homeserver/local_http_router.cpp:4063-4070`;
  `src/homeserver/media_service.cpp:825-870`
- **Detail:**
  - The decoder fork and exec, pipe I/O and decode, up to a 10 s timeout, all run with the
    lock held.
  - There is no thumbnail cache, so every request re-forks.
  - This contradicts the project convention of releasing the mutex for slow work
    (`docs/threat-model.md` ~1090).
- **Fix:**
  - Copy the bytes, release the lock around `generate_thumbnail`, and re-acquire.
  - Add an LRU thumbnail cache and a per-user concurrency cap.
- **Test:** GIVEN a decoder stub that sleeps 5 s WHEN a thumbnail request and a
  `/versions` request run concurrently THEN `/versions` completes first.

### MED-7 — Federation media download skips the trust-and-safety media policy

- **Severity:** low · **Attacker:** A3 · **Verdict:** confirmed
- **Location:** `src/homeserver/local_http_router.cpp:2243-2246`;
  `src/homeserver/media_service.cpp:64-75`
- **Detail:** only record state (quarantined or removed) is enforced. Media policy rules
  and the policy-server hook apply to client routes only.
- **Fix:** route the federation provider through `media_policy_decision`.
- **Test:** GIVEN a media policy rule blocking ID X WHEN a signed federation request
  downloads X THEN the response is 403 or 404.

### MED-8 — The thumbnail worker's crop path can request an enormous intermediate image

- **Severity:** low (contained by the sandbox) · **Attacker:** A2 · **Verdict:** confirmed
- **Location:** `src/media/thumbnail_worker_main.cpp:178-185`, `:248-266`, `:345-361`
- **Detail:**
  - The crop fill is `max(target, source × ratio)` with no pixel budget.
  - A 1×4096 source cropped to 1000×4096 asks for about 16 GB. `resize` throws and there
    is no `try`, so the worker terminates.
- **Fix:**
  - Budget the fill in 64-bit arithmetic, or crop and scale in a single pass.
  - Catch exceptions in the worker's `main`.
- **Test:** GIVEN a 4096×1 PNG WHEN a 1×2048 crop is requested THEN the worker returns a
  clean error.

### Area 9 — hardening notes

- Declared types that cannot be sniffed (video, audio, WebP, docx, `text/plain;
  charset=…`) mismatch the sniffed type. They are silently quarantined, answered 200 with
  a content URI, and then return 451 forever.
- `make_multipart_boundary` falls back to a constant boundary if the RNG fails
  (`repository.cpp:679-682`). The response should fail instead.
- `media_id_is_safe` permits NUL, control characters and backslash.
- Quarantine and removal apply per record, not per content hash, so re-uploading
  quarantined bytes produces an available ID.
- The federation `/media/thumbnail` endpoint and the `/download/{server}/{id}/{fileName}`
  route do not exist.

### Area 9 — coverage gaps

- Not examined: the parent-side handling of a thumbnail worker crash, the `RLIMIT_AS`
  value, and how the JSON serializer handles invalid UTF-8 in `dispatch_err`.

---

## Area 10 — Database, persistence and migrations

**Result:** 10 findings confirmed: 1 high, 3 medium, 6 low. The `type` half of DB-6 was
refuted.

**How DB-1 was verified:** the verifier checked it against a live PostgreSQL 16.13
cluster, driving `libpq` with the same `PQexecParams` call shape as the server.

**What holds:**
- No SQL injection: every runtime value is bound as a parameter, and DDL identifiers
  come from an allowlist.
- Prior fixes M-10 (the migration lease and ledger re-check), M-05, 0.12.5 finding 24,
  and fail-closed handling of a schema newer than the binary.
- M-08 holds as documented: the values are redacted from logs, but stored in plaintext.

**Only partly fixed:** M-09 was fixed for `media_blobs.bytes` alone (see DB-1 and DB-6).

### DB-1 — On PostgreSQL the server cannot read back its own signing key after a restart

- **Severity:** high (availability of the server identity; the default backend)
- **Attacker:** none needed
- **Verdict:** confirmed empirically
- **Location:**
  - `src/database/persistent_store.cpp:1042-1055` (write)
  - `src/database/postgresql_store.cpp:308-318`, `:369-420` (BLOB translated to BYTEA),
    `:571-586` (read, not decoded)
  - `src/homeserver/room_service.cpp:302-307`, `:1856-1905`, `:1952-1966`, `:2170-2176`
- **Rule:**
  - `docs/database-persistence.md`: binary columns must round-trip byte-exactly.
  - The earlier report's Resolution section flagged this column as "very likely" broken
    and needing confirmation against a live PostgreSQL.
- **Path:**
  1. The secret (`secretbox:v1:…`) is bound as a text parameter into a `BYTEA` column,
     where it is stored intact.
  2. On load, `row[4]` is copied as returned. With the default `bytea_output=hex`, that
     is `\x736563726574626f78…`.
  3. Only `media_blobs` is decoded on load.
  4. `decode_encrypted_secret_from_storage` requires the `secretbox:v1:` prefix, so the
     value falls to the legacy base64 branch, which yields the wrong size.
  5. `ensure_runtime_server_signing_key` returns `nullopt`, and the crypto provider holds
     no keys.
  6. `/_matrix/key/v2/server` then returns 500 ("server signing key unavailable").
- **Empirical result:**
  - The exact upsert returned
    `\x736563726574626f783a76313a51554a44524556475230684a536b744d` on `SELECT`.
  - `convert_from(secret_key,'UTF8')` returned the original, so the stored bytes are
    correct; only the read path is broken.
- **Impact:** after its first restart, a PostgreSQL deployment cannot sign events or
  federation requests until the row is repaired by hand. No test round-trips this column
  through PostgreSQL.
- **Fix:**
  - Decode BYTEA on load. Existing rows hold raw ASCII bytes, so this is
    backward-compatible.
  - Set `binary=true` on the write path.
  - Audit every other `BLOB` column for the same asymmetry.
  - Add a PostgreSQL restart round-trip test.
- **Test:** GIVEN a PostgreSQL store holding a `secretbox:v1:` signing key WHEN the store
  is closed and reopened THEN `secret_key` equals the stored string AND
  `ensure_runtime_server_signing_key` returns the same key.

### DB-2 — On PostgreSQL, the federation worker's room snapshot stops refreshing once a room passes 128 events

- **Severity:** medium (upper end) · **Attacker:** none needed · **Verdict:** adjusted from
  high (main remains authoritative for writes) · **Status:** fixed in 0.12.19
- **Location:**
  - `src/database/postgresql_store.cpp:2024-2036`, `:2130-2140`, `:283-289`
  - `src/database/statement.cpp:121-123`
  - `src/database/persistent_store.cpp:1230-1238`
  - `src/federation_worker/worker_event_loop.cpp:906-912`
- **Spec:** "When a remote server makes a request, it MUST be verified to be allowed by
  the server ACLs."
- **Path:**
  1. `load_room_snapshot_impl` builds `IN ($1..$N)` with one parameter per event, and
     never chunks it.
  2. `prepared_statement_is_valid` rejects more than 128 parameters, so `reload_room`
     fails.
  3. The worker logs a warning and keeps serving `make_join`, `make_leave`,
     `make_knock`, `/backfill`, `/state`, `/state_ids`, `/get_missing_events`,
     `/hierarchy` and directory queries from the snapshot it loaded at startup.
  4. That snapshot carries stale ACLs, bans and state.
- **Fix:**
  - Use `= ANY($1::text[])` or a join, or chunk the list.
  - When a reload fails, mark the snapshot untrusted and route those reads to main.
- **Test:** GIVEN a PostgreSQL room with 200 events WHEN an `m.room.server_acl` event is
  committed and `reload_room` runs on a second handle THEN the reload succeeds AND the
  denied server is refused.

### DB-3 — The PostgreSQL backend silently runs on an in-memory store when `database.uri_file` is missing or empty

- **Severity:** medium · **Attacker:** operator error, or anyone able to delete the file ·
  **Verdict:** confirmed
- **Location:**
  - `src/main.cpp:214` (`allow_missing=true`)
  - `src/homeserver/runtime.cpp:112-122`, `:603-608`
  - `src/database/sqlite_store.cpp:1167-1169`
- **Detail:**
  - The server starts as `opened=true`, and every persist call reports success.
  - All users, tokens, revocations and rooms vanish on the next restart, and a new
    signing key is generated.
  - Nothing tells the operator.
- **Fix:** when `backend=postgresql`, treat an unreadable or empty URI as a fatal startup
  error. Reserve the memory backend for an explicit, test-only entry point.
- **Test:** GIVEN `database.backend=postgresql` and a missing `uri_file` WHEN
  `start_runtime` runs THEN it fails.

### DB-5 — Security-relevant database writes are discarded with `std::ignore`

- **Severity:** medium (needs a database write fault) · **Attacker:** A2 holding a stale
  credential; users served removed content · **Verdict:** confirmed · **Status:** fixed in
  0.12.19
- **Location:**
  - `src/homeserver/media_service.cpp:975`, `:1120-1123`, `:1146`, `:1168-1172`
  - `src/homeserver/auth_service.cpp:1298-1299`, `:1371-1376`, `:1629`, `:1773-1774`,
    `:1830`
  - `src/database/persistent_store.cpp:832-847`
- **Rule:** `docs/database-persistence.md:735-741`: "Auth and room mutations fail the
  request when required persistent writes fail." That is not true for these paths.
- **Detail:**
  - Admin quarantine and remove update memory and report success even if the database
    write fails. After a restart, the content is served again.
  - Refresh-reuse revocation, logout, device deletion and password-change revocations
    ignore persistence failures.
  - `revoke_access_tokens_for_device` returns 0 on failure, which cannot be told apart
    from "nothing to revoke".
  - After a restart, the "revoked" tokens are hydrated as live. That matters most on
    password change, the compromise-recovery action. AUTH-1's correctness notes list
    one of these call sites.
- **Fix:** check every result, persist before applying, and return 5xx on failure.
- **Test:** GIVEN a backend that fails writes WHEN an admin quarantines media or a user
  changes their password THEN the request fails AND the reopened store matches memory.

### DB-4 — The membership row is written in a separate transaction from the event and current state

- **Severity:** low (needs a crash or write fault in a narrow window) · **Verdict:**
  confirmed mechanics; adjusted from medium
- **Location:** `src/homeserver/room_service.cpp:962-980` (and the similar sequences at
  `:2885-2911`, `:4147-4182`, `:4390-4404`, `:4552-4590`);
  `src/homeserver/runtime.cpp:507-521`
- **Detail:**
  - A ban can commit while the membership row still says `join`.
  - Hydration rebuilds `room.members` from that row, so the banned user regains read
    access.
  - Nothing reconciles the two at startup.
- **Fix:**
  - Write the event, state, membership and invite cleanup in one transaction.
  - Reconcile the membership table from `current_state` at hydration.
- **Test:** GIVEN a ban event persisted but its membership write failed WHEN the store is
  reopened THEN the user is not a member.

### DB-6 — PostgreSQL text parameters are cut at the first NUL byte, and `state_key` may contain one

- **Severity:** low (needs state power) · **Attacker:** A2 or A3 with state power ·
  **Verdict:** adjusted. The `type` half is refuted: `event_type_is_valid` rejects
  control characters.
- **Location:** `src/database/postgresql_store.cpp:308-316`; `src/events/event.cpp:214-220`;
  `src/core/query_params.cpp:85-100`; `migrations/001_initial_schema.sql:31`
- **Detail:**
  - libpq text parameters are C strings, so a `state_key` of `"\0x"` reaches the
    database as `""`.
  - That collides with the room's real empty-key row: it either fails the event with 500
    or makes the database diverge from memory.
  - SQLite binds by length, so the two backends behave differently.
- **Fix:**
  - Reject NUL in `state_key` during event validation, and in percent-decoded path
    values.
  - Reject NUL in text `BoundValue`s.
- **Test:** GIVEN a PostgreSQL store WHEN an event arrives with `state_key="\0x"` THEN it
  is rejected before any write.

### DB-7 — Every persisted write opens a fresh database connection while the global mutex is held

- **Severity:** low (a documented design: ADR-0009 and capability-gaps line 28) ·
  **Verdict:** adjusted
- **Location:** `src/database/postgresql_store.cpp:2205-2231`;
  `src/database/sqlite_store.cpp:1172-1181`
- **Detail:** this is a throughput limit, and it amplifies the DoS findings in Areas 1
  and 3.
- **Fix:** use the already-configured `database.pool_size` for write connections.
- **Test:** GIVEN 200 concurrent sends WHEN they are persisted THEN the connections opened
  are at most `pool_size`.

### DB-8 — TLS to PostgreSQL is neither required nor documented

- **Severity:** low · **Verdict:** confirmed
- **Location:** `src/database/postgresql_store.cpp:1704-1719`;
  `docs/user-manual.md:1188`
- **Detail:** libpq defaults to `sslmode=prefer`, which neither verifies the server nor
  resists downgrade.
- **Fix:** for non-loopback hosts, require `sslmode=verify-full` or an explicit opt-out,
  and document it.
- **Test:** GIVEN a remote host with no `sslmode` WHEN the connection string is validated
  THEN it is rejected.

### DB-9 — Connection-string redaction leaks passwords that are spaced or quoted

- **Severity:** low · **Attacker:** A6 with log access · **Verdict:** confirmed (the
  algorithm was ported and tested)
- **Location:** `src/database/postgresql_store.cpp:196-217`, `:1751-1813`
- **Detail:**
  - `password = 'sup er'` is not redacted at all.
  - `password='sup er'` becomes `password=redacted er'`.
  - Both forms are legal libpq syntax, and the string is logged on every connection
    open.
- **Fix:** never log the connection string; log only the host and database name.
- **Test:** GIVEN `host=x password='a b'` WHEN it is redacted THEN neither `a` nor `b`
  appears.

### DB-10 — SQLite is opened without symlink, mode or `secure_delete` protections

- **Severity:** low (packaged `0750` directories mitigate) · **Attacker:** A6 ·
  **Verdict:** adjusted
- **Location:** `src/database/sqlite_store.cpp:125-176`
- **Fix:** open with `SQLITE_OPEN_NOFOLLOW` and file mode 0600, and set
  `PRAGMA secure_delete=ON` and `trusted_schema=OFF`. See also ISO-6.
- **Test:** GIVEN a fresh store WHEN it is opened THEN the file mode is 0600 AND a
  symlinked path is refused.

### Area 10 — hardening and correctness notes

- **Text-ordered stream IDs.** Stream IDs are `TEXT` and loaded with `ORDER BY
  stream_id` (`sqlite_store.cpp:647-746`). After a restart, to-device messages and
  account data load with "10" before "9".
- **Broad role grants.** `packaging/postgresql/provision-roles.sql:92-102` gives the
  runtime role `UPDATE`/`DELETE` on `audit_log`, `admin_actions` and
  `schema_migrations`. The login role belongs to both the migration and runtime roles.
- **No-op pragma.** `PRAGMA foreign_keys=ON` does nothing, because no migration declares
  a foreign key.
- **Two migration sources.** Migrations are compiled into `migration.cpp`, while
  `migrations/*.sql` feed only `--plan`. Nothing checksums one against the other, so
  they can drift.
- **Push-rule documentation is wrong.** `docs/todos/capability-gaps.md:76` says push-rule
  CRUD is implemented. Only `GET` of the default ruleset exists
  (`client_server.cpp:11400-11440`), and the `push_rules` table is unused.

### Area 10 — coverage gaps

- Not read: `schema.cpp` and `migrations/002`–`017`, except through the compiled
  catalogue.
- The key-backup, presence, filter, profile and notification persistence functions were
  not read.

---

## Area 11 — Configuration, observability, admin and metrics endpoints, packaging

**Result:** 5 findings confirmed, all low. Two claims were refuted: `access_token` query
parameters reaching the audit log, and remote response bodies reflected into client
errors.

The auditor also proposed OPS-1, an unauthenticated audit flood. That is AUTH-1's
mechanism, so it is recorded as an addendum to AUTH-1 below instead of a separate finding.

**What holds:**
- The config parser and validator refuse unknown keys, duplicate keys, out-of-range
  values and insecure combinations.
- Admin routes require `require_admin` and are served on the client listener only.
- Metrics use static labels only, so there is no cardinality explosion.
- No exception text, SQL or file path reaches clients.
- The shipped example config keeps registration off and enforces TLS or reverse-proxy
  declarations.
- Every wrap is a `[wrap-file]` fetched over HTTPS with a `source_hash`, and
  `verify-wrap-pins.sh` enforces this.
- Prior fixes H-05, M-11, L-05, M-01, L-13, and 0.12.5 findings 22 and 23, all hold.

### AUTH-1 addendum — The audit log is also loaded whole at startup and concatenated whole by the admin endpoint

- **Location:**
  - `src/database/postgresql_store.cpp:1076-1089` and `src/database/sqlite_store.cpp:631-634`:
    `SELECT … FROM audit_log ORDER BY …` with no `LIMIT`, into `store.audit_log`.
  - `src/homeserver/runtime.cpp:950-981`: `GET /_merovingian/admin/audit` builds a single
    string from every row while the runtime mutex is held.
  - `src/homeserver/client_server.cpp:8765`, `:8797`, `:8826-8827`: the 503, 413 and 429
    paths each write a further audit row carrying the raw target, which can be up to
    8 KiB.
- **Effect:** AUTH-1's flood becomes a startup-time memory and latency problem that
  survives restarts.
- **Fix, in addition to AUTH-1's:**
  - Add retention and a `LIMIT` to the load.
  - Page the admin endpoint.
  - Stop mirroring the whole table in memory.

### OPS-2 — Raw request targets, query strings included, are stored in `audit_log.target`

- **Severity:** low (medium where a reverse proxy runs without `trusted_proxies`, so all
  clients share one bucket) · **Attacker:** A1 · **Verdict:** adjusted from medium
- **Location:** `src/homeserver/client_server.cpp:2831`, `:8765`, `:8797`, `:8826-8827`;
  `src/homeserver/local_services.cpp:106-123`
- **Spec:** the registration-token validity endpoint takes the secret as a query
  parameter ("`token` | string | **Required:** The token to check validity of").
- **Detail:**
  - When such a request is rate-limited, or answered 413 or 503, the audit row, and the
    debug-level `audit.append` log line, store `?token=<registration token>` in
    plaintext.
  - That defeats the Argon2id hashing of the token file.
  - The diagnostic fields on the same lines already use `sanitized_http_target`.
  - `docs/threat-model.md` (~663) lists the token-in-logs leak as fixed, which is true of
    logs only.
- **Fix:** sanitise and truncate `target` inside `append_local_audit` or
  `make_audit_event`, so every caller is covered.
- **Test:** GIVEN a rate-limited caller WHEN it sends
  `GET …/registration_token/validity?token=SECRET` THEN no audit row or log line contains
  `SECRET`.

### OPS-3 — Malformed media quota values silently mean "unlimited"

- **Severity:** low (needs an operator typo) · **Verdict:** adjusted from medium
- **Location:** `src/config/config.cpp:1083-1088` (only `max_upload_size` is validated);
  `src/media/runtime_media.cpp:35-46`; `src/config/AGENTS.md:29`
- **Detail:**
  - `security.media.max_total_size=10G` fails `parse_size_limit` and becomes 0, which
    means no limit, with no warning.
  - `src/config/AGENTS.md` documents suffixes (`100M`, `1G`) that the parser rejects.
- **Fix:**
  - Validate non-empty values in `validate()`.
  - Correct the AGENTS.md text.
  - Log the effective quotas at startup.
- **Test:** GIVEN `security.media.max_size_per_user=1G` WHEN the config is validated THEN
  it is rejected.

### OPS-4 — Token lifetimes accept negative or huge values

- **Severity:** low · **Verdict:** confirmed
- **Location:** `src/config/config_parser.cpp:627-640`, `:1123`;
  `src/homeserver/auth_service.cpp:460-467`; `src/homeserver/client_server.cpp:9728`,
  `:9768`
- **Detail:**
  - A negative value silently disables expiry, although only `0` is documented to do
    that.
  - Values above about 9.2e12 ms overflow when converted to nanoseconds.
  - `expires_in_ms` is advertised as 0 or negative for tokens that never expire.
- **Fix:**
  - Reject negative values and values above a sane bound.
  - Omit `expires_in_ms` when there is no expiry.
- **Test:** GIVEN `access_token_lifetime_ms=-1` WHEN the config is validated THEN a
  finding is returned.

### OPS-5 — The Docker image and the deb and BSD packages build at `-O0`, and so fail the startup hardening gate

- **Severity:** low (fails closed; documented as scaffolding) · **Verdict:** adjusted
- **Location:**
  - `meson.build:7-11`, `:108-113`
  - `Dockerfile:21-34`
  - `scripts/build-deb.sh:14-23`, `build-freebsd-pkg.sh:14-21`, `build-netbsd-pkg.sh:28`,
    `build-openbsd-pkg.sh:18`
  - `src/platform/hardening_self_check.cpp:42-43`, `:184-190`, `:222-223`
- **Detail:**
  - With no `buildtype`, Meson builds `debug`, so `_FORTIFY_SOURCE` is never defined and
    `main.cpp:950-955` refuses to start.
  - The Dockerfile also lacks `libpq-dev` and `libpq5`, copies neither worker binary, and
    pins its base image by tag rather than digest.
- **Fix:**
  - Pass `--buildtype=release` in every packaging path, or set it in `default_options`.
  - Ship the worker binaries and runtime libraries.
  - Pin the base image by digest.
  - Add a CI step that runs the packaged binary's startup gate.
- **Test:** GIVEN the deb or Docker build WHEN the binary starts THEN every hardening
  check reports `enabled`.

### OPS-6 — The bootstrap admin password file skips the secret-file checks

- **Severity:** low · **Attacker:** A6 · **Verdict:** confirmed
- **Location:** `src/main.cpp:495-505`, `:858-870`; `docs/user-manual.md:261-268`,
  `:1234`
- **Detail:**
  - The file is read with `ifstream` (following symlinks) into a plain `std::string`.
    There is no owner, mode or symlink check.
  - The manual's example writes the password to `/tmp/admin-pw`, a path another local
    user can pre-create.
  - The manual says the server exits after bootstrap; the code continues to open its
    listeners.
- **Fix:**
  - Apply `is_secure_secret_file`, read into `SecretBuffer`, and wipe it afterwards.
  - Change the manual example to a 0700 directory.
  - Make the code and the manual agree on whether the server exits.
- **Test:** GIVEN a 0644 or symlinked password file WHEN the server starts with
  `--bootstrap-admin-password-file` THEN startup is refused.

### Area 11 — hardening notes

- **Hot reload is not wired.** No SIGHUP handler exists and `apply_reload` has no
  production caller. `src/config/AGENTS.md` and `logger.hpp:236-243` still describe hot
  reload.
- **Reload diffing is incomplete.** If reload is ever wired, `build_reload_plan` does not
  compare about 20 keys, including `database.*`, `reverse_proxy.*`,
  `security.media.max_*`, `server.oidc.*` and `server.sso.*`.
- **Loose integer parsing.** `std::stoul` on several `server.http.*`, timeout and CORS
  keys accepts trailing junk and a leading `-`.
- **`server.trusted_proxies` is not validated.** Malformed entries silently never match,
  which puts every client into one rate-limit bucket.
- **The log file is truncated on open**, so a restart erases the previous run's log.
- **`/_matrix/federation/v1/version` discloses the exact version.**
- **meson.build sets no minimum version for system libsodium, OpenSSL, libpq or
  libcurl.**

---

## Overall summary

**101 verified findings:** 1 critical, 23 high, 31 medium and 46 low.

| Area | Critical | High | Medium | Low |
|------|---------:|-----:|-------:|----:|
| 1 Authentication and sessions | 0 | 2 | 3 | 7 |
| 2 Client-Server authorisation | 0 | 4 | 4 | 4 |
| 3 HTTP transport and DoS | 0 | 3 | 3 | 2 |
| 4 Federation inbound | 1 | 5 | 3 | 3 |
| 5 Event engine | 0 | 5 | 4 | 3 |
| 6 Outbound and SSRF | 0 | 1 | 3 | 4 |
| 7 Cryptography and IPC | 0 | 1 | 1 | 4 |
| 8 Isolation and hardening | 0 | 1 | 2 | 5 |
| 9 Media | 0 | 0 | 5 | 3 |
| 10 Database | 0 | 1 | 3 | 6 |
| 11 Config, observability, packaging | 0 | 0 | 0 | 5 |
| **Total** | **1** | **23** | **31** | **46** |

### Recommended fix order

The order puts the effort where the risk is.

1. **Room takeover and room confidentiality.**
   - FED-1: `send_join` state not bound to the room.
   - FED-2: federation reads with no in-room check.
   - CSAZ-1: sliding sync with no membership check.
   - CSAZ-2 and CSAZ-3: read gates and history visibility.
   - CSAZ-4: private read receipts.

   Any local user, or any federating server, can take over or read rooms.

2. **Spec divergence in the event engine.**
   - EVT-1 to EVT-4 and EVT-6: restricted-join signature, the power-levels required
     level, partitioning, the topological sort, and negative power levels.
   - FED-5 and FED-6: invites overwriting bans, and knocks recorded as joins.

   These let a remote server get events accepted that conformant servers reject.

3. **Sandbox boundary.**
   - CRY-1: the signing oracle.
   - ISO-1: pre-hardening threads.
   - ISO-2: signal and rlimit syscalls.
   - CRY-2: the IPC queue.

   A compromised federation worker currently escapes its sandbox and signs as the server.

4. **Cheap unauthenticated denial of service.**
   - HTTP-1, HTTP-2 and HTTP-8: worker-pool starvation.
   - HTTP-5: SIGPIPE.
   - AUTH-1 and AUTH-11: unbounded audit rows and retained statements.
   - AUTH-4: Argon2 under the global lock.
   - FED-4: forged-signature lockout.
   - FED-7: EDU fan-out.
   - OUT-7: the unenforced remote-fetch opt-in.

5. **Durability and correctness of security state.**
   - DB-1: the PostgreSQL signing key.
   - DB-2: stale worker snapshots.
   - DB-3: silent in-memory fallback.
   - DB-5: ignored write failures.
   - MED-1: the legacy media freeze.
   - MED-2 and MED-3: quarantine and removal.

6. **Everything else**, in the order listed within each area.

### Documentation found to be wrong about the code

These statements should be corrected with the fixes, per `docs/AGENTS.md`.

- **`docs/threat-model.md`:**
  - `:496-521`, bad-faith resident server (FED-1).
  - `:372-379`, forgery prevented by the worker split (CRY-1).
  - `:1137-1171`, parking and per-IP caps (HTTP-1).
  - `:429-436`, SQLite "readable" (ISO-4).
  - `:723` and `:786`, `deny_ip_ranges` (OUT-8).
  - `:469`, worker restart back-off (ISO-3).
  - ~`:663`, registration token redaction (OPS-2).
- **ADRs:**
  - ADR-0015 (CRY-1).
  - ADR-0065 (CRY-2).
  - ADR-0068 and `docs/media-repository.md:135` (MED-1).
  - ADR-0072 (HTTP-1).
- **Other docs:**
  - `docs/hardening.md:174-178`, SIGPIPE (HTTP-5).
  - `docs/auth-identity.md:509-541`, lockout (AUTH-2).
  - `docs/http-transport.md:490-492` and `:546`, path coalescing (HTTP-3).
  - `docs/database-persistence.md:735-741`, failed writes fail the request (DB-5).
  - `docs/crypto-boundary.md:218-220` (CRY-6).
  - `docs/todos/capability-gaps.md:76`, push-rule CRUD (Area 10 notes).
  - `docs/todos/capability-gaps.md:95`, redactions (CSAZ-11).
- **AGENTS.md files and code comments:**
  - `src/config/AGENTS.md`, size suffixes and hot reload (OPS-3; Area 11 notes).
  - `src/appservice/registration.cpp:544-546`, sender "created at startup" (AUTH-3).

### Limits of this audit

- **Static review, apart from targeted experiments.** Nothing was built and no test suite
  was run. The verifiers ran scratch experiments for OUT-1 (libcurl and glibc), ISO-1
  (per-thread seccomp) and DB-1, DB-6 and DB-9 (PostgreSQL 16.13 and libpq). Every other
  finding rests on reading the code and the spec.
- **Coverage gaps** are listed at the end of each area. The largest are:
  - the appservice YAML loader and outbound client;
  - `src/identity/`;
  - the IPC frame serialisers;
  - TLS private-key handling;
  - BSD pledge and Capsicum behaviour;
  - the persistence functions for key backup, presence, filters and notifications.
- **Severities are relative to the attacker models above.** Findings rated for A5 assume
  code execution in a worker has already been gained.

