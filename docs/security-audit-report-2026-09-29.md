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
| 3 | HTTP transport, TLS and request-level DoS | pending |
| 4 | Federation inbound (X-Matrix, PDU ingestion, keys, backfill, membership) | pending |
| 5 | Event engine (auth rules, state resolution, redaction, canonical JSON) | pending |
| 6 | Outbound requests and SSRF (discovery, push, identity, appservice, remote media) | pending |
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

