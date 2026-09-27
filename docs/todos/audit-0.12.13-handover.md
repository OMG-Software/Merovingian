# Handover: the 0.12.13 security branch

**Branch:** `fix/audit-critical-high-0.12.13`, pushed to `origin`.
**Written:** 2026-09-27. The session that produced this work has ended; nobody
from it is available to answer questions. This file is the complete record.

**Verified state at handover** (full run 2026-09-26, read from
`build-wsl/meson-logs/testlog.txt`): `Ok: 54`, `Fail: 0`, no timeouts.
`[backfill]` passes 5 unit, 11 integration and 5 conformance cases. Working
tree clean. 91 commits ahead of `origin/main`. `meson.build` still says
`0.12.12` — the version bump is part of "Before merge".

**No pull request has been opened.**

## How this branch came about

A full security audit of v0.12.12 ran across six surfaces (federation inbound
and worker IPC; the event pipeline; client auth, crypto and canonical JSON;
HTTP and network transport; database and config; media, platform and
observability). One specialist auditor per surface, with every finding verified
against the code and the spec rather than trusted from the auditor's report.
That produced five high findings, eight medium and seven low.

Fixing the state-resolution finding uncovered a far larger problem: state
resolution never ran in production. Inbound PDUs were authorised only against
current state and then written straight into `current_state`, so concurrent
state events resolved as last-writer-wins and a peer controlling delivery
order could choose our room state. That became ADR-0064, a four-phase rewrite
of PDU ingestion, which is the bulk of this branch.

## Read first

1. `AGENTS.md` (root) — binding project rules, especially "Verifying Work".
2. The module `AGENTS.md` for whatever you touch (`src/<module>/AGENTS.md`).
3. ADRs added on this branch: `docs/adr/0062` through `0069`. ADR-0064
   (spec-conformant PDU ingestion) is essential context for D1 and item 12.
4. `docs/matrix-v1.19-spec/` — the only authority. Not Synapse, not memory.

Next free numbers: ADR **0070** (add a line to `docs/adr/index.md` in the same
commit), migration **017** (a new migration must be classified for the
federation worker's table allowlist, or a source-tree test fails).

## What is done on this branch (do not redo)

* **Thumbnail decoder fail-closed.** `harden()` discarded every result,
  including seccomp; the decoder now exits before reading any input if any
  control fails.
* **Finding N1: the federation worker can no longer reach the signing key.**
  It held both halves of the secret: the master key (read only to derive its
  IPC key) and, through shared database credentials, the encrypted signing
  key. It now receives only a derived IPC key over an inherited fd (ADR-0062),
  logs in to PostgreSQL as its own least-privilege role that can read nine
  tables and never the `secret_key` column, and is confined by Linux Landlock
  with a guard refusing any rule that covers a configured secret.
* **State resolution v2/v2.1 correctness.** The auth difference and the v12
  conflicted state subgraph are computed; v2.1 starts from an empty map; power
  ordering reads each event's own `auth_events` rather than its own content (a
  self-elevating power-levels event previously ranked itself); the v12 create
  event is derived from the room ID. ADR-0063 records the fail-closed rule and
  the auth-chain walk cap.
* **ADR-0064 phases A, B1, B2.** Delta state groups (migration 015, with an
  `event_edges(prev_event_id)` index without which seeding was quadratic);
  state resolution running in production over forward extremities; receipt
  checks in spec order on both `/send` and the membership path — a hash
  mismatch redacts rather than rejects, and authorisation runs against the
  event's own `auth_events`, then the state before it, then current state,
  with rejected and soft-failed statuses and client-delivery filtering. Ban
  evasion through old parts of the DAG is now soft-failed as the spec
  requires, instead of being hard-rejected and lost.
* **Phase C backfill**, both halves: `/get_missing_events` plus `/event/{id}`,
  and the `/state_ids` + `/event_auth` fallback (but see D1, unratified).
* **H1** master key file permission checks. **H2** per-channel IPC in-flight
  cap with a retryable 5xx (ADR-0065, superseding ADR-0027's premise that the
  queue's producer was trusted — it is the worker). **M1** SSRF filtering for
  the push gateway and identity clients, plus CGNAT/NAT64/multicast ranges.
  **M2** password re-auth shares the login lockout (ADR-0066). **M3** PDU size
  and field limits before hashing (ADR-0067). **M4** `m.federate` for room
  versions 1-5. **M5** random media IDs and the legacy endpoint freeze
  (ADR-0068, migration 016).
* **Backfill hardening.** Backfilled events are authorised against the state
  before them, and failures are stored `rejected` with an after-state equal to
  the state before them. A `/state_ids` snapshot is rejected outright if it
  names an event from another room, an event already stored `rejected`, a
  duplicate `(type, state_key)`, or a non-state event.

## Decisions (answered by the user in writing on 2026-09-27)

* **D1: ratified with a tightening.** Events verified only through
  `/event_auth` carry no state group (ADR-0070). Done: ADR-0069's deciders and
  date corrected, ADR-0064's inaccurate "Deciders" line removed at the user's
  direction, tests under `[event_auth_outlier]`.
* **D2: main re-verifies relayed PDU signatures with its own
  `remote_key_resolver`** (cache first, network fetch on a miss with the locks
  released). Passing key material from the worker was rejected: a compromised
  worker would supply both the key and the signature. Done (ADR-0071), for all
  three PDU-bearing relays, together with the signing-key cache race it
  exposed; tests under `[worker_relay_signature]` and
  `[signing-key][concurrency]`.
* **D3: deferred** to a separate cleanup branch; tracked in
  `docs/todos/capability-gaps.md`.

Further answers from the user on 2026-09-27, in writing:

* **Item 1:** default per-IP connection cap 64
  (`server.http.max_connections_per_ip`); addresses in
  `server.trusted_proxies` are exempt from the accept-time cap.
* **Item 4 addition:** `effective_client_ip` must take the rightmost
  `X-Forwarded-For` entry that is not a trusted proxy, not the leftmost
  (which the client controls when the proxy appends to the header).

The original text of each decision follows for context.

### D1. Ratify or revert the `/state_ids` fallback rework

The fallback was made functional by ADR-0069 (commits `8604f0c0`, `1857c790`,
`495b6efb`): snapshot state events and their `/event_auth` auth chains are
verified by signature, hash and their own `auth_events`, then stored as
outliers **without** requiring a local state-before; the snapshot cap went
from 100 to 1000 events and a separate 100-call budget was added.

The agent that wrote it was asked to present options and not implement it. It
implemented it anyway. On review the direction matches what conformant servers
do, and the relaxation is correctly scoped: `allow_auth_events_only` is `true`
only at the two `/event_auth` call sites
(`src/homeserver/local_http_router.cpp:3248` and `:3255`), so every other path
keeps the state-before check.

**Regardless of the decision, ADR-0069 is factually wrong and must be
corrected:** it lists "Deciders: James Chapman, Claude Code" for a decision the
user never made, and is dated 2026-09-22 although the work landed on the 25th
and 26th.

If ratified, record this residual risk in `docs/threat-model.md`: an outlier
stored this way has an after-state of its own `auth_events` plus itself, so a
later event's state-before can be a thin, origin-shaped state rather than the
room's real prior state. The damage is bounded by the current-state check
(receipt step 6), which still soft-fails, for example, a banned user's event —
**no test proves that bound yet, and one should exist.**

### D2. Main does not re-verify PDU signatures from the worker

Main persists PDUs the worker relays without re-checking their Ed25519
signatures ("main trusts the worker's prior check", near the `pdu_ingest`
handler in `src/homeserver/worker_pool.cpp`; recorded as an accepted risk in
`docs/threat-model.md`). N1 removed the worker's route to the signing key,
which limits the damage, but a compromised worker can still inject events
impersonating any sender the room's state authorises. Option to put to the
user: the worker passes the key material it verified with, and main
re-verifies against its own key cache without making network calls.

### D3. The `state_group_edges` table

Unused since ADR-0064 chose single-parent state groups. Dropping a table needs
explicit approval under `migrations/AGENTS.md`.

## Binding rules and lessons from this branch

Every one of these cost real time here.

- **Tests first, and record the failure.** Commit the test, build, and quote
  the failing assertion before implementing. Agents repeatedly shipped code
  whose tests had never failed and therefore proved nothing.
- **Commit at every compiling step.** Work was lost to interruptions three
  times because nothing was committed.
- **Never relax a check to make a test pass.** An agent relaxed the room-v12
  rule forbidding `m.room.create` in `auth_events` (rooms/v12.md rule 3.2 says
  reject) to fix hand-built fixtures; it was reverted. When a correct check
  breaks a fixture, fix the fixture. When it breaks a production path, find the
  real bug — there, no v12 room could resolve a fork at all.
- **Never record a decision a human did not make.** Do not invent deciders or
  dates in an ADR, a CHANGELOG entry or a doc. A false attribution outlives any
  code defect, because future readers trust it.
- **Mocks model policy, not the environment.** Landlock's unit tests all
  passed while the real kernel rejected every rule (`EINVAL` for directory
  rights on a file, `EPERM` without `no_new_privs`, `SIGSYS` because the worker
  inherits main's seccomp filter across `execve`). Kernel, filesystem and
  network contracts need real-environment tests.
- **A test that SKIPs is not a pass.** The real-kernel Landlock test skipped on
  every refusal, hiding a live bug. Skip only on the precondition itself.
- **Check code is reachable before checking it is correct.** The state resolver
  was fixed, green, and dead for a whole phase.
- **A check on what you fetched is not a check on what you already had.** The
  `/state_ids` fallback verified every downloaded event, then trusted any
  matching event already in the store — including events from other rooms and
  events deliberately stored as `rejected`.
- **Never hold `runtime.mutex` across a network call**
  (`src/homeserver/AGENTS.md`, "The runtime lock and blocking calls"; this
  shipped as a server-wide stall three times).
- **Never clear `FD_CLOEXEC` in the parent.** Place inherited fds with
  `posix_spawn_file_actions_adddup2` (see `make_worker_secret_pipe`).
- Project rules: RAII, no raw owning pointers (prefer references), no
  `new`/`delete`/`malloc`, `std::ignore` not `(void)`, namespace
  `merovingian::<module>`, BDD `SCENARIO`/`GIVEN`/`WHEN`/`THEN` tests, update
  docs and the `CHANGELOG.md` 0.12.13 section with every change, an ADR for any
  decision with a rejected alternative.
- A repo hook reformats whole C++ files on edit. That is accepted; do not work
  around it through the shell.

## Verification (every item)

1. `python build.py wsl` **in the background** — it takes 9+ minutes and
   exceeds the 10-minute foreground limit. Wait for it to finish.
2. Read `Ok:` / `Fail:` / `Timeout:` from the end of
   `build-wsl/meson-logs/testlog.txt` yourself. `build.py` exits 0 even when
   suites fail. A timeout is a failure, usually a deadlock.
3. Prove new tests ran with a tag-filtered run:
   `wsl ./build-wsl/tests/merovingian-unit-tests "[your_tag]"`. Catch2
   registers scenarios as `"Scenario: x"`, so filter by tag, not by name.
4. Faster iteration: `wsl ninja -C build-wsl tests/merovingian-unit-tests`
   builds one binary; still finish with a full `build.py` run.
5. `testlog.txt` records output only for failing tests, so grepping it for a
   scenario name cannot prove that scenario ran.

---

## Remaining work, in recommended order

### 1 (medium): no per-IP connection cap

Connection admission is bounded only by a global queue depth and a global
parked keep-alive cap. One host can open connections just below the slowloris
thresholds, fill the global budget and lock everyone else out; the per-IP rate
limiter only runs after a request is parsed.

Where: `src/net/thread_pool.cpp`, the accept loops
(`src/homeserver/http_server.cpp`, `src/net/`), and `effective_client_ip` in
`src/homeserver/local_http_router.cpp` for how the client address is derived.
At accept time you see the peer address, which is the proxy's when a reverse
proxy is in front — handle that deliberately, document it, and make the cap
configurable (classified in `src/config/reload_policy.cpp` /
`reload_plan.cpp`). Group IPv6 by /64, sharing code with item 3. Release the
slot with an RAII guard.

Tests: connections from one address beyond the cap are refused while another
address still connects; closing frees a slot; error paths cannot leak a slot.
Concurrency scenarios must assert on the main thread only — Catch2 assertions
are not thread-safe.

### 2 (low): `knock_restricted` rejected on the direct-join path

`src/events/authorization.cpp` accepts only `restricted` and `restricted_v2`
on the join path. Spec rooms/v10.md rule 5.5: "If the `join_rule` is
`restricted` or `knock_restricted`". Fails closed, so legitimate joins are
refused. Add a conformance test citing the rule.

### 3 (low): `m.room.aliases` redaction wrong for room versions 6 and 7

`src/events/redaction.cpp` keeps `aliases` for every version before v11.
rooms/v6.md removed `m.room.aliases` from the redaction algorithm, so for v6
and v7 the content must be stripped to `{}`. Otherwise our redacted form, and
therefore the reference hash, differs from other servers'. The `room_v1_v7`
bucket is coarser than the spec here. Conformance tests for v5 (keeps
`aliases`), v6 and v7 (strip).

### 4 (low): IPv6 clients can escape rate limits within one /64

Rate-limit buckets use the literal client address (`effective_client_ip`).
Group IPv6 by /64 with a configurable prefix. Tests: two addresses in one /64
share a bucket; different /64s do not; IPv4 unchanged.

### 5 (low): user directory search returns deactivated users

`POST /_matrix/client/v3/user_directory/search` in
`src/homeserver/client_server.cpp`. Exclude deactivated accounts. Returning
every local user is allowed by the spec, so do not change that without asking.

### 6 (low): no refresh-token reuse detection

`refresh_local_session`, `src/homeserver/auth_service.cpp`. When an
already-rotated refresh token is presented again, revoke the whole session
lineage. Not a spec requirement; defence in depth.

### 7 (low): dead authorization code

`membership_policy_allows` and `authorize_event` in
`src/events/authorization.cpp` have no production callers and look wrong for
ban and knock. Confirm with `grep`, then delete them and their tests rather
than fixing them.

### 8 (low, reliability): the worker can start without its IPC fd

`src/homeserver/worker_supervisor.cpp` does
`adddup2(client_fd, kWorkerIpcFd)`. If the socketpair returns
`client_fd == 3`, that is a same-fd `dup2`, which some libcs treat as a no-op
that leaves `FD_CLOEXEC` set, so the worker starts with no IPC socket.
Relocate the fd off the fixed numbers first, as `make_worker_secret_pipe`
does.

### 9 (low): backfill processes fetched events in response order

`backfill_missing_pdu_references` handles `/get_missing_events` results in the
order the remote returned them. A child arriving before its parent has no
state-before yet and is dropped: safe, but it wastes usable events. Sort by
`depth` ascending before verifying and storing.

### 10 (low, project rule): raw pointer in the IPC in-flight guard

`struct InFlightGuard` in `src/homeserver/worker_pool.cpp` stores
`ipc::IpcChannel*`. Safe as written (the captured `shared_ptr` keeps the
channel alive) but it breaks "no raw pointers, prefer references". Make it a
reference member.

### 11 (low, cosmetic): underscores in `docs/hardening.md`

Headings and text read "Cross_platform", "Build_time",
"Position_independent" and similar, from an old find-and-replace. Replace with
hyphens and check no link anchor depends on the old spelling. This one also
exists on `main`.

### Pre-existing flake (not caused by this branch)

`tests/integration/test_http_server_listener_flow.cpp` asserts `FD_CLOEXEC` on
an accepted socket it locates by scanning `/proc/self/fd` for a matching port;
under parallel load it can match a different descriptor. It passes when run
alone. Match on the socket's full local and peer address instead.

## Before merge

1. Resolve D1 (and ideally D2 and D3) with the user.
2. Bump the version to `0.12.13` everywhere `docs/versioning.md` lists
   (`meson.build` still says `0.12.12`). The bump happens once per branch, at
   merge time.
3. Make sure the `CHANGELOG.md` 0.12.13 section covers every item finished,
   and remove resolved entries from this file and from
   `docs/todos/capability-gaps.md`.
4. Run the full suite one last time and read the counts.
5. Open the pull request with the headings `AGENTS.md` requires: Summary, What
   changed, Why it changed, CI tests (modified tests and new tests listed
   separately).
