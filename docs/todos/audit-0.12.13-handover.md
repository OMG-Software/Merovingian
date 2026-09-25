# Handover: remaining work on the 0.12.13 security branch

Branch: `fix/audit-critical-high-0.12.13`. `meson.build` still says `0.12.12`
(see "Before merge"). State at handover (2026-09-25): full suite green,
`Ok: 54`, `Fail: 0`, no timeouts, verified by reading
`build-wsl/meson-logs/testlog.txt`.

This file is for an agent picking the work up cold. Read it in full before
starting. Every location below was checked against the branch tip on the date
above; re-check with `grep` before editing, because line numbers drift.

## Read first

1. `AGENTS.md` (root) — binding project rules, especially "Verifying Work".
2. The module `AGENTS.md` for whatever you touch (`src/<module>/AGENTS.md`).
3. ADRs added on this branch: `docs/adr/0062` to `0068` — above all `0064`
   (spec-conformant PDU ingestion) for items 1, 2 and 12.
4. `docs/matrix-v1.19-spec/` — the only authority. Not Synapse, not memory.

Next free numbers: ADR **0069** (add it to `docs/adr/index.md`), migration
**017** (must be classified for the federation worker's table allowlist — a
source-tree test fails otherwise).

## Already done on this branch (do not redo)

Thumbnail decoder fail-closed; N1 (the federation worker cannot reach the
signing key: IPC key over an fd, least-privilege PostgreSQL login, Landlock);
state resolution v2/v2.1 fixes; ADR-0064 phases A, B1, B2 and the first half
of C (`/get_missing_events` + `/event/{id}` backfill); H1 (master key file
permission checks); H2 (per-channel IPC in-flight cap, ADR-0065); M1 (SSRF
filtering for push and identity clients); M2 (password re-auth shares the
login lockout, ADR-0066); M3 (PDU size and field limits, ADR-0067); M4
(`m.federate` for room versions 1–5); M5 (random media IDs and legacy
endpoint freeze, ADR-0068, migration 016).

## Binding rules and lessons from this branch

Each of these caused a real defect or a wasted cycle here.

- **Tests first, and record the failure.** Commit the test, build, and quote
  the failing assertion before implementing.
- **Commit at every compiling step.** Agents on this branch lost all their
  work to interruptions three times because nothing was committed.
- **Never relax a check to make a test pass.** When a correct check breaks a
  fixture, fix the fixture; when it breaks a production path, find the real
  bug. If you believe a check is wrong, stop and show the spec text.
- **Mocks model policy, not the environment.** Anything touching the kernel,
  filesystem, or network needs a real-environment test. A SKIP is not a pass.
- **Check code is reachable before checking it is correct.**
- **Never hold `runtime.mutex` across a network call** (see
  `src/homeserver/AGENTS.md`, "The runtime lock and blocking calls").
- **Never clear `FD_CLOEXEC` in the parent**; place inherited fds with
  `posix_spawn_file_actions_adddup2` (see `make_worker_secret_pipe`).
- Project rules: RAII, no raw owning pointers (prefer references), no
  `new`/`delete`/`malloc`, `std::ignore` not `(void)`, namespace
  `merovingian::<module>`, BDD `SCENARIO`/`GIVEN`/`WHEN`/`THEN` tests, update
  docs and the `CHANGELOG.md` 0.12.13 section with every change, ADR for any
  decision with a rejected alternative.
- A repo hook reformats whole C++ files on edit. That is accepted; do not work
  around it through the shell.

## Verification (every item)

1. `python build.py wsl` **in the background** (9+ minutes; exceeds the
   10-minute foreground limit). Wait for it to finish.
2. Read `Ok:` / `Fail:` / `Timeout:` from the end of
   `build-wsl/meson-logs/testlog.txt`. `build.py` exits 0 even when suites
   fail. A timeout is a failure.
3. Prove new tests ran with a tag-filtered run, e.g.
   `wsl ./build-wsl/tests/merovingian-unit-tests "[your_tag]"`.
4. Faster iteration: `wsl ninja -C build-wsl tests/merovingian-unit-tests`
   builds one binary; still finish with a full `build.py` run.

---

## Remaining items, in recommended order

### 1 (high, security): backfilled events skip the state-before check

- **Problem.** Phase C fetches missing events and stores them as outliers
  with a recorded after-state group. It checks each fetched event against its
  own named `auth_events`, but never against the state immediately **before**
  it (receipt check step 5), and then records an after-state that **includes
  the event itself**. A malicious origin can craft an event its chosen
  `auth_events` permit (for example an old power-levels event from when it
  held power) but that the real prior state forbids. Sent directly, step 5
  rejects it. Delivered as a "missing" event, it becomes part of the
  state-before of the next PDU that references it, and can reach current state
  through resolution.
- **Where.** `verify_and_store_backfilled_event`,
  `src/homeserver/local_http_router.cpp:2557`. The auth-events check ends just
  before `compute_state_before` / `compute_state_after` (`state_after` at
  about line 2677); the state group is recorded at about line 2726. Compare
  `ingest_pdu_event`, which runs steps 4, 5 and 6 in order.
- **Spec.** `server-server-api.md`, "Checks performed on receipt of a PDU"
  step 5, and "Rejection": a rejected event is stored so later events that
  reference it can be authorised, but "not updating with the rejected event"
  — its after-state is the state before it.
- **Fix.** After computing `state_before`, authorise the event against it
  (build the map with `build_auth_event_map_from_entries` and
  `fill_create_from_room_state`, as `ingest_pdu_event` does). On failure,
  store it with status `rejected` and record its after-state group as
  `state_before` (not including itself). Do not simply drop it: later events
  may legitimately reference a rejected event.
- **Tests (tag `[backfill]`, plus a conformance case citing step 5).** A
  fetched event that passes its own `auth_events` but fails the state before
  it is stored as `rejected`, its after-state excludes it, and a PDU that
  lists it as a `prev_event` does not see its state. Record this failing
  first. Add the positive case: a fetched event passing both checks is stored
  as an outlier whose after-state includes it.

### 2 (high): the `/state_ids` fallback of phase C was never built

- **Problem.** The design decided in ADR-0064 is: `/get_missing_events`
  first; if a gap remains, fetch `/state_ids` and `/event_auth` at the event
  from the sending server, fetch any events we lack, verify **every** one
  (signature, hash, auth against its own `auth_events`, and item 1's
  state-before check), drop any that fail, and use the verified set as a
  snapshot state group for the state before the event. If the claimed state
  cannot be verified, reject the PDU. Only the first half exists, so a gap
  that `/get_missing_events` cannot fill still leaves the PDU at
  `missing_prev_state` and the room stalls.
- **Where.** `backfill_missing_pdu_references`,
  `src/homeserver/local_http_router.cpp:2741`; the existing fetchers
  `fetch_get_missing_events` (`:2439`) and `fetch_event_by_id` (`:2514`) show
  how to build and sign an outbound request and release locks around it. The
  store API for a snapshot group is `create_or_reuse_state_group`.
- **Constraints.** Everything is driven by untrusted remote input. Bound the
  number of state IDs and auth events fetched per PDU (add constants next to
  `k_max_backfill_outbound_calls` at `:2375`), fail closed, and never hold
  `runtime.mutex` across a network call.
- **Tests (tag `[backfill]`).** A gap `/get_missing_events` cannot fill falls
  back to `/state_ids`; a claimed state naming an event that fails any check
  has that event dropped; state that cannot be verified leads to rejection;
  a server returning an enormous state set hits the cap and the PDU is
  rejected, not partially applied.
- **Docs.** ADR-0064's phase C heading currently says "(shipped)" while the
  body says only "the first half" is implemented. Fix the heading now, and
  record the fallback when it lands.

### 3 (medium): no per-IP connection cap

- **Problem.** Connection admission is bounded only by a global queue depth
  and a global parked keep-alive cap. One host can open connections just below
  the slowloris thresholds, fill the global budget, and lock everyone else out;
  the per-IP rate limiter only runs after a request is parsed.
- **Where.** `src/net/thread_pool.cpp`, the accept loops
  (`src/homeserver/http_server.cpp`, `src/net/`), and `effective_client_ip`,
  `src/homeserver/local_http_router.cpp:3242`. At accept time you see the
  peer address, which is the proxy's when a reverse proxy is in front —
  handle that deliberately (document it, and make the cap configurable).
- **Fix.** Per-source-address connection accounting at accept time, released
  by an RAII guard on close, with a config key classified in
  `src/config/reload_policy.cpp` / `reload_plan.cpp`. Group IPv6 by /64
  (shares code with item 7).
- **Tests.** Connections from one address beyond the cap are refused while
  another address still connects; closing frees a slot; error paths cannot
  leak a slot (a concurrency scenario; assert on the main thread only —
  Catch2 assertions are not thread-safe).

### 4 (needs a user decision — do not implement without asking)

Main persists PDUs relayed by the worker without re-checking their Ed25519
signatures ("main trusts the worker's prior check", near the `pdu_ingest`
handler in `src/homeserver/worker_pool.cpp`; documented as an accepted risk
in `docs/threat-model.md`). N1 limits the damage, but a compromised worker can
still inject events impersonating any sender the room's state authorises. The
option to put to the user: the worker passes the key material it verified
with, and main re-verifies against its own key cache without network calls.

### 5 (low): `knock_restricted` rejected on the direct-join path

`src/events/authorization.cpp:1163` accepts only `restricted` and
`restricted_v2`. Spec: rooms/v10.md rule 5.5, "If the `join_rule` is
`restricted` or `knock_restricted`". Fails closed: legitimate joins are
refused. Conformance test citing the rule.

### 6 (low): `m.room.aliases` redaction wrong for room versions 6 and 7

`src/events/redaction.cpp:87` keeps `aliases` for every version before v11.
rooms/v6.md removed `m.room.aliases` from the redaction algorithm, so for v6
and v7 its content must be stripped to `{}`. Otherwise our redacted form and
reference hash differ from other servers'. The `room_v1_v7` redaction bucket
is coarser than the spec here — fix the version predicate, and add
conformance tests for v5 (keeps `aliases`), v6 and v7 (strip).

### 7 (low): IPv6 clients can escape rate limits within one /64

Rate-limit buckets use the literal client address (`effective_client_ip`,
`src/homeserver/local_http_router.cpp:3242`). Group IPv6 addresses by /64
(configurable prefix) for the rate-limit key. Tests: two addresses in the same
/64 share a bucket; different /64s do not; IPv4 is unchanged.

### 8 (low): user directory search returns deactivated users

`POST /_matrix/client/v3/user_directory/search`,
`src/homeserver/client_server.cpp:13461`. Exclude deactivated accounts.
(Returning every local user is allowed by the spec; do not change that
without asking.)

### 9 (low): no refresh-token reuse detection

`refresh_local_session`, `src/homeserver/auth_service.cpp:1267`. When a
refresh token that has already been rotated is presented again, revoke the
whole session lineage. Not a spec requirement; defence in depth. Record the
decision in an ADR if you choose between alternatives.

### 10 (low): dead authorization code

`membership_policy_allows` (`src/events/authorization.cpp:807`) and
`authorize_event` (`:939`) have no production callers and look wrong for ban
and knock. Delete them and their tests rather than fixing them. Confirm there
are no callers with `grep` first.

### 11 (low, reliability): the worker can start without its IPC fd

`src/homeserver/worker_supervisor.cpp:389` does
`adddup2(client_fd, kWorkerIpcFd)`. If the socketpair returns
`client_fd == 3`, that is a same-fd `dup2`, which some libcs treat as a no-op
that leaves `FD_CLOEXEC` set, so the worker starts with no IPC socket.
Relocate the fd off the fixed numbers first, as `make_worker_secret_pipe`
does.

### 12 (low): backfill processes fetched events in response order

`backfill_missing_pdu_references` handles `/get_missing_events` results in
the order the remote returned them. A child that arrives before its parent
has no state-before yet and is dropped. That is safe (fail closed) but loses
events we could use. Sort by `depth` ascending before verifying and storing.

### 13 (low, project rule): raw pointer in the IPC in-flight guard

`struct InFlightGuard`, `src/homeserver/worker_pool.cpp:385`, stores
`ipc::IpcChannel*`. It is safe (the captured `shared_ptr` keeps the channel
alive) but breaks the "no raw pointers, prefer references" rule. Make it a
reference member.

### 14 (low, cosmetic): underscores in `docs/hardening.md`

Headings and text read "Cross_platform", "Build_time",
"Position_independent" and similar (line 11 onward), from an old
find-and-replace. Replace with hyphens. Check no link anchors depend on the
old spelling.

### Pre-existing flake (fix only if time allows)

`tests/integration/test_http_server_listener_flow.cpp` asserts `FD_CLOEXEC`
on an accepted socket it finds by scanning `/proc/self/fd` for a matching
port; under parallel load it can match a different descriptor. It passes when
run alone. Match on the socket's full local and peer address instead.

## Needs a user decision (ask; do not decide)

- Item 4 above.
- **`state_group_edges` table.** Unused since ADR-0064 chose single-parent
  state groups. Dropping it needs explicit approval under
  `migrations/AGENTS.md`.

## Before merge

1. Bump the version to `0.12.13` everywhere `docs/versioning.md` lists
   (`meson.build` still says `0.12.12`). The bump happens once per branch, at
   merge time.
2. Make sure `CHANGELOG.md`'s 0.12.13 section describes every item finished,
   and remove resolved entries from this file and from
   `docs/todos/capability-gaps.md`.
3. Open the pull request with the headings `AGENTS.md` requires: Summary,
   What changed, Why it changed, CI tests (modified and new tests listed).
