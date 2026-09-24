# Handover: outstanding work from the 0.12.12 security audit

Branch: `fix/audit-critical-high-0.12.13` (pushed to origin; 0.12.13 in
`CHANGELOG.md`, `meson.build` still says `0.12.12` — see "Before merge").
State at handover (2026-09-24): full suite green, `Ok: 54`, `Fail: 0`, no
timeouts, verified by reading `build-wsl/meson-logs/testlog.txt`.

This file is for an agent picking the work up cold. Read it in full before
starting. Everything below was verified against the branch tip on the date
above; re-check a location with `grep` before editing it, because line numbers
drift.

## Read first

1. `AGENTS.md` (root) — binding project rules, especially "Verifying Work".
2. The module `AGENTS.md` for whatever you touch (`src/<module>/AGENTS.md`).
3. The ADRs this branch added: `docs/adr/0062` (federation worker holds no
   secret files), `0063` (fail closed on unreachable state-res auth-chain
   events), `0064` (spec-conformant PDU ingestion with delta state groups).
4. `docs/matrix-v1.19-spec/` — the only authority. Not Synapse, not memory.

## What is already done on this branch (do not redo)

- Thumbnail decoder hardening is fail-closed.
- Finding N1: the federation worker can no longer reach the server signing
  key — IPC key over an inherited fd (ADR-0062 part 1), a separate
  least-privilege PostgreSQL login over an fd with a table allowlist (part 2),
  and Linux Landlock with a secret-path overlap guard (part 3). This also
  resolves the audit's "worker has unrestricted `openat`" finding.
- State resolution v2/v2.1: auth difference, v12 conflicted state subgraph,
  empty-start map, power ordering read from each event's own `auth_events`,
  v12 create event derived from the room ID.
- ADR-0064 phases A, B1, B2: delta state groups (migration 015), state
  resolution running in production over forward extremities, receipt checks in
  spec order on both `/send` and the membership path (hash mismatch redacts;
  auth against `auth_events`, state-before, then current state; rejected and
  soft-failed statuses; client-delivery filtering).

## Binding rules and lessons from this branch

These are not generic advice. Each one caused a real defect or a wasted cycle
on this branch.

- **Tests first, and record the failure.** Commit the test, build, and quote
  the failing assertion before implementing. Several agents skipped this and
  delivered code whose tests never proved anything.
- **Commit at every compiling step.** Agents on this branch lost all their
  work to usage-limit interruptions three times because nothing was committed.
- **Never relax a check to make a test pass.** An agent relaxed the room-v12
  rule forbidding `m.room.create` in `auth_events` (rooms/v12.md rule 3.2
  says reject) to fix hand-built fixtures; it was reverted. When a correct
  check breaks a fixture, fix the fixture. When it breaks a production path,
  find the real bug — here it was that no v12 room could resolve a fork.
- **Injected-ops mocks model policy, not the kernel.** The Landlock unit tests
  all passed while the real kernel rejected every rule (`EINVAL` for directory
  rights on a file, `EPERM` without `no_new_privs`, `SIGSYS` because the worker
  inherits main's seccomp filter across `execve`). Anything touching kernel,
  filesystem, or network contracts needs a real-environment test.
- **A test that SKIPs is not a pass.** The real-kernel Landlock test skipped
  on every refusal, hiding a real bug. Skip only on the precondition itself.
- **Check that code is reachable before checking it is correct.** The state
  resolver was fixed and green for a phase before anyone noticed production
  never called it.
- **Never clear `FD_CLOEXEC` in the parent.** `main` is multithreaded; place
  inherited fds with `posix_spawn_file_actions_adddup2` onto fixed child fd
  numbers (see `make_worker_secret_pipe`, `src/homeserver/worker_supervisor.cpp`).
- **Security properties belong in code, not comments.** The push gateway
  client's comment claims "SSRF-safe resolution" over a raw `getaddrinfo`
  (item M1 below).
- Project rules: RAII, no raw owning pointers, no `new`/`delete`/`malloc`,
  `std::ignore` not `(void)`, namespace `merovingian::<module>`, BDD
  `SCENARIO`/`GIVEN`/`WHEN`/`THEN`, update docs and `CHANGELOG.md` (0.12.13
  section) with every change, ADR for any decision with a rejected
  alternative (next free number: **0065**; add it to `docs/adr/index.md`).
- A repo hook reformats whole C++ files on edit. That is accepted; do not work
  around it through the shell.

## Verification (every item)

1. `python build.py wsl` **in the background** (it takes 9+ minutes and
   exceeds the 10-minute foreground limit). Wait for it to finish.
2. Read `Ok:` / `Fail:` / `Timeout:` from the end of
   `build-wsl/meson-logs/testlog.txt`. `build.py` exits 0 even when suites
   fail. A timeout is a failure.
3. Prove new tests ran by tag, e.g.
   `wsl ./build-wsl/tests/merovingian-unit-tests "[your_tag]"`. Catch2 names
   scenarios `"Scenario: x"`, so filter by tag.
4. For faster iteration, `wsl ninja -C build-wsl tests/merovingian-unit-tests`
   builds one binary; still finish with a full `build.py` run.
5. Known pre-existing flake, not yours:
   `tests/integration/test_http_server_listener_flow.cpp` asserts
   `FD_CLOEXEC` on an accepted socket it finds by scanning `/proc/self/fd`;
   under parallel load it can pick the wrong descriptor. It passes alone. Fix
   it only if you have time (match on the socket's peer and local address,
   not the port alone).

---

## Work items, in recommended order

### H1 (high): the master key file skips the secret-file checks

- **Problem.** Every other secret file (database URI files, TLS private keys,
  registration token) is checked at start-up for owner-only, non-executable,
  regular-file, TOCTOU-safe metadata. The master key file — the root secret
  every derived key comes from — is opened with a plain `std::ifstream` and
  never checked. A group- or world-readable master key, or a symlink swapped
  in, is accepted.
- **Where.** `validate_existing_secret_files`, `src/main.cpp:196`
  (`master_key_file` appears nowhere in `src/main.cpp`);
  `load_master_key_material`, `src/crypto/master_key.cpp:31`.
- **Fix.** Add `security.secrets.master_key_file` to
  `validate_existing_secret_files` using the existing
  `validate_existing_secret_file_metadata` helper, required when set. Since
  N1, only the main process reads this file; the worker receives a derived key
  over an fd, so no worker change is needed.
- **Tests (`[secret_files]` or the existing tag for that function).** A
  master key file with group/other permissions is refused at start-up; a
  symlinked one is refused; an owner-only `0400` regular file is accepted.
- **Docs.** `docs/hardening.md` (secret file permissions list),
  `docs/user-manual.md`, `CHANGELOG.md`. Note operators upgrading may need
  `chmod 0400` on the master key.

### H2 (high): main's IPC handler pool has no queue cap

- **Problem.** Requests the federation worker sends to main (`pdu_ingest`,
  `sign_request`, `membership_ingest`) are queued on a thread pool with no
  depth cap. ADR-0027 left it unbounded on the premise that "their producer
  is the local supervisor, not a remote peer". That premise is false: the
  producer is the worker, the least-trusted process. A compromised worker can
  flood main until it runs out of memory, taking down client traffic too.
- **Where.** `handler_pool_{cfg_.relay_threads}`,
  `src/homeserver/worker_pool.cpp:791`. `net::ThreadPool` takes a
  `max_queue_depth` (0 = unbounded) — see `include/merovingian/net/thread_pool.hpp`.
- **Decided by the user (do not re-litigate).** Supersede ADR-0027 for the
  IPC pools with a **per-channel cap on in-flight requests**; a request over
  the cap gets an **explicit error reply**. The worker then answers the remote
  server with a 5xx and the remote retries the transaction, so nothing is lost
  silently — which was ADR-0027's reason for staying unbounded.
- **Work.** Write ADR-0065 (status accepted; mark ADR-0027 "superseded by
  ADR-0065" for the IPC pools only — the connection-queue half of 0027 still
  stands; never delete or renumber). Add a config key for the cap with a
  sensible default, classified restart-required in
  `src/config/reload_policy.cpp` / `reload_plan.cpp`. Make sure the worker
  maps the error reply to a 5xx toward the remote, not a 4xx (a 4xx would make
  the remote drop the PDU).
- **Tests.** A channel at the cap rejects the next request with the explicit
  error and does not queue it; requests below the cap are processed; the
  worker turns the error into a retryable 5xx; a worker flooding requests
  cannot grow main's queue past the cap (a concurrency scenario — see
  `tests/unit/AGENTS.md` on thread-safety tests; assert on the main thread
  only, Catch2 assertions are not thread-safe).

### C (high): ADR-0064 phase C — fetch missing events, then verified state

- **Problem.** An inbound PDU whose `prev_events` (or named `auth_events`)
  we don't have returns `PduIngestionStatus::missing_prev_state` and is not
  stored. That is correct and fail-closed, but a gap in room history is never
  repaired, so a room can stall.
- **Decided by the user (see ADR-0064, do not re-litigate).** First
  `/get_missing_events` from the sending server, bounded in event count and
  depth. If a gap remains, fetch `/state_ids` and `/event_auth` at the event
  from the server that sent the PDU, fetch any events we lack, and run
  signature, hash, and auth checks on **every** returned event (each against
  its own `auth_events`) before using the set as state. An event that fails is
  dropped from the claimed state. If the claimed state cannot be verified,
  reject the PDU — never apply it on unverified data. Cap all outbound fetches
  per PDU and per transaction.
- **Where to start.** Grep `missing_prev_state` (13 sites in `src/`); the
  receipt path is `ingest_pdu_event` and the membership acceptor in
  `src/homeserver/local_http_router.cpp`, with state bookkeeping in
  `src/homeserver/state_bookkeeping.cpp`. We already SERVE these endpoints
  (`src/federation/event_query.cpp`); the outbound client side needs building
  or finding — check `src/homeserver/room_service.cpp` and the federation
  outbound path first. Outbound calls go out through the worker/proxy path
  like the rest of federation; read `src/federation_worker/AGENTS.md` for the
  relay rules.
- **Constraints.** Never hold `runtime.mutex` across a network call (see
  `src/homeserver/AGENTS.md`, "The runtime lock and blocking calls" — this
  has shipped as a server-wide stall three times). Everything is driven by
  untrusted remote input: bound every loop and fetch, fail closed.
  Fetched state must be stored as a snapshot state group (the phase A store
  API: `create_or_reuse_state_group`) and events not on our timeline as
  status `outlier`.
- **Tests (`[pdu_ingestion]`, conformance with spec citations).** A PDU with
  one missing prev_event is fetched via `/get_missing_events` and then
  accepted; a gap that `/get_missing_events` cannot fill falls back to
  `/state_ids`; a `/state_ids` response naming an event that fails its
  signature, hash, or auth check has that event dropped; a response that
  cannot be verified leads to rejection, not acceptance; the fetch caps hold
  against a malicious server that returns endless events. Use the existing
  mock remote servers in the federated-join integration tests.
- **Docs.** ADR-0064 (mark phase C shipped, with implementation notes),
  `docs/event-engine.md`, `docs/threat-model.md`, `CHANGELOG.md`, and remove
  the "Phase C has not started" note from `docs/todos/capability-gaps.md`.

### M1 (medium): push gateway and identity server clients skip SSRF filtering

- **Problem.** Both clients resolve the target host with the raw resolver,
  which never applies the private/loopback address filter, despite comments
  claiming "SSRF-safe resolution". Any user can register a pusher whose URL
  resolves to `127.0.0.1`, `169.254.169.254`, or RFC 1918 space. Outbound TLS
  verification (`VERIFYPEER`/`VERIFYHOST`) is currently the only thing stopping
  a full SSRF; it still allows blind internal port probing.
- **Where.** `discovery_.upstream().lookup_addresses(...)` at
  `src/push/push_gateway_client.cpp:332` and
  `src/identity/identity_client.cpp:318`. The filter is `address_set_allowed`,
  `src/federation/server_discovery.cpp:191`; the classifiers are
  `ipv4_is_private_or_loopback` / `ipv6_is_private_or_loopback`,
  `src/federation/security.cpp:50` and `:58`.
- **Fix.** Provide a filtering resolution path and use it in both clients.
  Better: make it hard to call the unfiltered resolver by accident (e.g. a
  type only the filtering path can produce). The appservice client's
  unfiltered use is intentional (operator-configured URL) — leave it, and say
  so in a comment.
- **Also (low, same change):** the classifiers miss CGNAT `100.64.0.0/10`,
  the NAT64 prefix `64:ff9b::/96`, and multicast/reserved ranges. Add them
  with tests.
- **Tests.** A pusher whose host resolves to loopback, link-local metadata,
  RFC 1918, or CGNAT is refused before any connection; a public address is
  allowed. Use the existing test-forced-resolution seam in the push client.

### M2 (medium): password re-authentication bypasses the login lockout

- **Problem.** `/login` has a progressive lockout; the six endpoints that
  re-check a password (cross-signing key upload, password change, account
  deactivation, device deletion, and two more) go straight to the Argon2id
  check with no lockout. A stolen access token without the password allows
  about 90 guesses a minute indefinitely; a correct guess can replace the
  cross-signing master key.
- **Where.** `verify_local_user_password`,
  `src/homeserver/auth_service.cpp:1790` (6 callers in `client_server.cpp`);
  the lockout functions `failed_login_lockout_remaining_ms` /
  `record_failed_login` in the same file.
- **Fix.** Apply the lockout check and failure recording inside
  `verify_local_user_password`, so every caller gets them. Decide whether
  re-auth failures share the `/login` counter (recommended: yes — an attacker
  should not get a separate budget) and record that in the code comment.
- **Tests.** Repeated wrong passwords through each endpoint trip the
  lockout; a correct password during lockout is still refused; `/login` and
  re-auth share the counter.

### M3 (medium): no size or field-length limits on federation PDUs

- **Problem.** The spec caps an event at 65536 bytes and `sender`, `room_id`
  and `state_key` at 255 bytes; `matrix_id_is_valid` checks only a minimum
  length, and `state_key` is not validated at all. Client requests are covered
  by the 64 KiB body cap; federation PDUs are not. `prev_events` must be at
  most 20 and, in v12, `auth_events` at most 10 (rooms/v12.md event format).
- **Where.** `src/events/event.cpp:137` (`matrix_id_is_valid`) and `:213`
  (`state_key`); limits in `include/merovingian/events/limits.hpp`
  (`max_prev_events_per_event = 20` exists but is used for local events —
  confirm whether inbound PDUs enforce it).
- **Fix.** Enforce all of these at parse time, before hashing or authorising,
  on the inbound path. Spec: client-server-api.md "Size limits".
- **Tests.** An oversized PDU, an over-long `sender`/`room_id`/`state_key`,
  and over-long `prev_events`/`auth_events` arrays are each rejected before
  any hashing; boundary values (exactly the limit) are accepted.

### M4 (medium): `m.federate: false` is not enforced for room versions 1–5

- **Where.** `src/events/authorization.cpp:1013` gates the rule on
  `room_v6_plus || room_v12`. The rule is in rooms/v1.md too (rule 3).
- **Fix.** Apply it for every room version. Watch the same class of bug:
  version buckets in `room_version_policy` are coarser than the spec's
  per-version changes.
- **Tests (conformance).** A remote sender's event in a v1–v5 room created
  with `m.federate: false` is rejected; a local sender's is allowed.

### M5 (medium): legacy unauthenticated media, and guessable media IDs

- **Problem.** `/_matrix/media/v3/download` and `/thumbnail` serve all media
  without authentication; the spec (v1.12+) says to freeze them for media
  uploaded after adoption of authenticated media. Media IDs are a sequential
  counter plus a 12-hex-character prefix of the **content** digest, so anyone
  with a candidate file can confirm whether it was uploaded here.
- **Where.** `make_media_id`, `src/media/repository.cpp:102`; the legacy
  routes at `src/homeserver/client_server.cpp:9791` (download) and `:9801`
  (thumbnail).
- **Decided by the user.** Both: freeze the legacy endpoints for media
  uploaded after the upgrade (spec SHOULD, v1.12), **and** make media IDs
  random. Existing media stays reachable on the legacy endpoints.
- **Work.** Random IDs from libsodium `randombytes_buf` with enough entropy
  (at least 128 bits), URL-safe encoding. Record a freeze marker (e.g. an
  upload timestamp or a boolean on the media row) — that needs a migration
  (next number: **016**) and must be classified for the federation worker's
  table allowlist (a source-tree test fails otherwise). Consider an ADR if
  you choose between alternatives for the freeze marker.
- **Tests.** New media IDs are random and do not reveal the content digest;
  media uploaded after the freeze is refused on `/media/v3/*` and served on
  `/client/v1/media/*`; media uploaded before it is still served on both.

### M6 (medium): no per-IP connection cap

- **Problem.** Connection admission is bounded only by a global queue depth
  and a global parked keep-alive cap. One host can open connections just below
  the slowloris thresholds, fill the global budget, and lock everyone else out;
  the per-IP rate limiter only runs after a request is parsed.
- **Where.** `src/net/thread_pool.cpp` (global queue), the listener and
  accept loops (`src/homeserver/http_server.cpp`, `src/net/`),
  `effective_client_ip` at `src/homeserver/local_http_router.cpp:2741` for
  how the client address is derived (note `X-Forwarded-For` is honoured only
  from `trusted_proxies`, and a per-IP cap at accept time sees the proxy's
  address — handle that deliberately).
- **Fix.** Per-source-address connection accounting at accept time, with a
  config key, released on close (RAII guard). Group IPv6 addresses by /64
  (see L3).
- **Tests.** Connections from one address beyond the cap are refused while
  another address still connects; closing a connection frees a slot; the
  accounting cannot leak on error paths.

### M7 (needs a user decision): main does not re-verify PDU signatures

The audit found that main persists PDUs relayed by the worker without
re-checking their Ed25519 signatures ("main trusts the worker's prior check",
`src/homeserver/worker_pool.cpp` near the `pdu_ingest` handler; documented as
an accepted risk in `docs/threat-model.md`). N1 removed the worker's route to
the signing key, which limits the damage, but a compromised worker can still
inject events impersonating any sender the room's state authorises. **Do not
change this without asking the user.** Option to present: the worker passes
the key material it verified with; main re-verifies against its own key cache
without making network calls.

### Low-severity items

- **L1.** `knock_restricted` is not accepted on the direct-join path —
  `src/events/authorization.cpp:1165` checks only `restricted` and
  `restricted_v2`. Spec: rooms/v10.md rule 5.5 ("`restricted` or
  `knock_restricted`"). Fails closed (legitimate joins refused).
- **L2.** `m.room.aliases` redaction keeps `aliases` for v6/v7 rooms —
  `src/events/redaction.cpp:87`. rooms/v6.md removed `m.room.aliases` from
  the redaction algorithm. The redacted form, and so the reference hash,
  differs from other servers'.
- **L3.** Rate-limit buckets use the literal client address; IPv6 clients can
  rotate through a /64 to escape the `auth_sensitive` tier. Group IPv6 by /64
  (configurable prefix).
- **L4.** The user directory returns deactivated users —
  `POST /_matrix/client/v3/user_directory/search`,
  `src/homeserver/client_server.cpp:13406`. Exclude them. (Returning all local
  users is allowed by the spec; optionally add a setting defaulting to the
  spec minimum of shared-room users.)
- **L5.** No refresh-token reuse detection —
  `refresh_local_session`, `src/homeserver/auth_service.cpp:1267`. On reuse
  of a rotated refresh token, revoke the whole session lineage. Not a spec
  requirement; defence in depth.
- **L6.** Dead code: `authorize_event` (`src/events/authorization.cpp:939`)
  and `membership_policy_allows` (`:807`) have no production callers and look
  wrong for ban/knock. Delete them (and their tests) rather than fix them.
- **L7.** Same-fd `dup2` hazard for the IPC socket:
  `src/homeserver/worker_supervisor.cpp:384` does
  `adddup2(client_fd, kWorkerIpcFd)`; if the socketpair returns
  `client_fd == 3`, it is a same-fd dup2, which some libcs treat as a no-op
  leaving `FD_CLOEXEC` set, so the worker starts with no IPC fd. Relocate as
  `make_worker_secret_pipe` does. Not a security issue; a start-up reliability
  one.
- **L8.** `docs/hardening.md` (also on `main`) has underscores where hyphens
  belong ("Cross_platform", "Build_time", "Position_independent"), apparently
  from an old find-and-replace. Cosmetic.

## Needs a user decision (ask; do not decide)

- **`state_group_edges` table.** Unused since ADR-0064 chose single-parent
  state groups. Dropping a table needs explicit approval under
  `migrations/AGENTS.md`. Recommendation: drop it in a later migration.
- **M7** above.

## Before merge

1. Bump the version to `0.12.13` everywhere `docs/versioning.md` lists
   (`meson.build` still says `0.12.12`). Per project practice the bump
   happens once per branch, at merge time.
2. Make sure `CHANGELOG.md`'s 0.12.13 section describes every item you
   finished, and remove the resolved entries from
   `docs/todos/capability-gaps.md` and this file.
3. Open the pull request with the headings `AGENTS.md` requires: Summary,
   What changed, Why it changed, CI tests (modified and new tests listed).
