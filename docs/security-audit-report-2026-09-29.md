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
| 7 | Cryptography, key management and worker IPC | pending |
| 8 | Process isolation and platform hardening (workers, seccomp, sandboxes) | pending |
| 9 | Media repository and thumbnailer | pending |
| 10 | Database, persistence and migrations | pending |
| 11 | Configuration, observability, logging and packaging | pending |

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
  token-gated) · **Verdict:** confirmed
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
  sub-claims are only partly verified
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

- **Severity:** medium · **Attacker:** A3 · **Verdict:** adjusted
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

