# Handover: fixing the HIGH/CRITICAL findings of the 2026-09-29 security audit

Written 2026-09-30 by the session that did the work, for whoever picks it up.
Source of the findings: `docs/security-audit-report-2026-09-29.md`.
Scope asked for: all HIGH findings. The one CRITICAL finding (FED-1) was included
because it outranks them. Medium and low findings are out of scope.

## Where things are

- **Branch:** `claude/loving-goldberg-670823`, pushed to origin. Base: `8a09ecb` (0.12.14).
- **Tip:** `694f97b` plus the commit that adds this handover.
- **Status:** 23 of the 24 findings are fixed and merged, one squash commit per group.
  HTTP-1 is not merged. The version bump, CHANGELOG and PR are also not done.
- **No PR exists yet.** Do not create one until HTTP-1, the version bump and the
  CHANGELOG are done, unless the user asks.

| Commit | Findings | ADR |
|---|---|---|
| `92d7644` | EVT-2 (power_levels held to `events["m.room.power_levels"]`), EVT-6 (negative user levels honoured) | — |
| `b148d08` | EVT-3 (state partition with 3+ groups), EVT-4 (Kahn topological power ordering) | — |
| `7bdd1bf` | HTTP-5 (SIGPIPE ignored in every `main`), ISO-1 (no thread before hardening; seccomp TSYNC; per-task self-check) | 0082 |
| `fd9b67b` | CRY-1 (worker signing oracle removed; refusing provider in the worker) | 0078 (supersedes part of 0015) |
| `7d8d699` | FED-4 (bad signatures charged per source address, not to the claimed origin; backoff decays) | 0081 |
| `c069379` | DB-1 (PostgreSQL bytea decoded on read, bound as binary on write) | — |
| `98f44c7` | FED-1, critical (send_join state bound to the joined room; own-domain events verified against our own keys; the resolver never fetches our own name) | 0083 |
| `e308145` | FED-2 (federation room reads require origin in room or world_readable; bounded `/get_missing_events`) | — |
| `8ae3520` | AUTH-1 (rate-capped unauthenticated audit rows; bounded windows; 255-byte fields), AUTH-11 (no retained statements) | 0080 |
| `ade54ca` | FED-3 (to-device sender binding and dedupe), FED-5 (inbound invite authorised; never overwrites a ban), FED-7 (device-list fan-out to room sharers only, deduped) | 0085 |
| `d127632` | CSAZ-1 (sliding sync room access), CSAZ-4 (`m.read.private` and `m.fully_read` privacy) | — |
| `387b3b8` | CSAZ-2 (read gates for initialSync, `/members`, `/state`), CSAZ-3 (history visibility on every client read path) | 0084 |
| `694f97b` | HTTP-2 (in-flight budget and deadlines for client-triggered outbound calls), OUT-7 (`remote_fetch_enabled` enforced before discovery) | 0079 |

ADR numbers: 0077 is reserved for HTTP-1 (in the WIP patch, see below). 0086 is unused.
No migrations were added; 018 is still free.

## Verification evidence

The last independent run, by the orchestrator, was on `387b3b8`, which contains every
merged group except HTTP-2/OUT-7. It used the conditions in "Environment notes" below:

- unit: `All tests passed (51877 assertions in 1609 test cases)`
- conformance: `All tests passed (14964 assertions in 866 test cases)`
- integration: `test cases: 263 | 262 passed | 1 skipped`. The skip is the root-only
  worker seccomp scenario. PostgreSQL scenarios were enabled.

`694f97b` (HTTP-2/OUT-7) was verified only by the agent that wrote it, on exactly that tree:
- unit: 1619 passed
- conformance: 866 passed
- integration: 271 passed, 1 skipped
- 51 meson script gates: OK

**The orchestrator did not re-run it.** Run the full suite on the tip before anything else.

The baseline at `8a09ecb` was all green under the same conditions: unit 1539,
conformance 835, integration 238 plus 1 skip.

## Outstanding work, in order

### 1. HTTP-1 (worker-pool starvation) and HTTP-8: unfinished, unverified

- **The patch.** `docs/handover/http-1-wip.patch` holds 4 commits on top of `694f97b`
  (`git format-patch` output). Apply it on a new branch with
  `git am docs/handover/http-1-wip.patch`, or use the local branch `fix/g9-http1` if this
  container still exists. Delete the patch file from the repo once it has been applied.
- **Done in the patch, per its commit messages:**
  - failing tests `[http-1]` and `[http-8]`;
  - `net::ConnectionParker`, one poll thread that owns connections awaiting input;
  - HTTP served through that dispatcher;
  - a configurable request pool.
- **In progress when interrupted:**
  - doc rewrites: `docs/http-transport.md`, `threat-model.md`, `user-manual.md`,
    `hardening.md` and `architecture.md`;
  - the module `AGENTS.md` files;
  - `config/merovingian.conf.example`;
  - ADR-0077, "No worker waits on a quiet connection", which also has to mark
    ADR-0072 as amended.
- **Not done:** building and running the full suite. Nobody has reviewed the diff
  (36 files, +3858/−1062).
- **Brief the patch was written against:**
  - The parker owns every connection that is not being served, both new and keep-alive.
    It dispatches to the pool only when the connection is readable (TLS: also when
    `SSL_pending`).
  - At most `max(1, pool/4)` connections per client address can be held by workers.
    Configured trusted proxies are exempt.
  - Minimum body rate after a 10 s grace: 16 KiB × (elapsed − 10 s).
  - Media-upload bodies above the normal cap only with a valid access token checked from
    the head; otherwise 401 before the body is read.
  - At most 1000 requests and 1 hour of lifetime per connection.
  - Pool size is a config key, default 16, range 4–256, restart required, and is wired to
    `main_request_pool_threads` so the HTTP-2 budget stays at pool/2.
  - Every new thread starts after hardening (ADR-0082).
- **Review it for:**
  - single ownership of each connection (parker XOR one worker);
  - lock order, and no I/O under the parker lock;
  - bounded shutdown;
  - no spin on connections parked at the per-client cap;
  - the ISO-1 ordering;
  - the smoke tests, which start the real server.

### 2. Version bump to 0.12.15

Follow the table in `docs/versioning.md`. Do all files in one commit:
- `meson.build`
- `src/main.cpp`
- `src/db_migrate.cpp`
- the packaging specs
- the `scripts/build-*.sh` scripts
- the packaging `%changelog` entries

### 3. `CHANGELOG.md`

Add a `## 0.12.15` section. The commit messages above are written to be the basis for it,
one bullet per group, citing finding IDs and ADRs. Mention these behaviour changes that
operators and clients will notice:
- history visibility is now enforced, and pre-state-group history is visible only to
  users who were joined when it was sent;
- banned users read state as of their ban;
- sliding sync limits: `timeline_limit` ≤ 100, and 256 subscriptions and `required_state`
  pairs each;
- the outbound proxy 429s;
- `remote_fetch_enabled=false` now really blocks remote media fetches;
- inbound `m.receipt` accepts only `m.read`;
- the audit window of 1024 rows;
- the new config key from HTTP-1.

### 4. Final verification, then the PR

Run the full suites, both script and smoke gates, and PostgreSQL. Only then open the PR.
PR body headings, from the user's preference and `AGENTS.md`:
- Summary
- What changed
- Why it changed
- Tests, with Updated and New subsections

## Residual risks and deliberate deviations recorded during review

Check these against the ADRs and threat model before calling the work done.

- **FED-1:** the `state` array of a send_join response is still not run through the auth
  rules. A bad-faith resident can lie about its own room, but only that room. The
  `store_server_signing_key` guard is a check-then-write, not atomic.
- **FED-2:** event lookups are linear scans, since the store has no index. The worker
  snapshot can be briefly stale, so a newly joined server may get 403 for a moment.
- **FED-3:** the `message_id` dedupe window lives in memory (65,536 entries, 24 h) and is
  lost on restart. The EDU `origin` relayed by the worker is still trusted; see FED-12,
  which is out of scope.
- **FED-5:**
  - Invite-only rooms we host: an invitee cannot join until the transaction copy of the
    invite arrives (ADR-0085).
  - An invite for an already-joined target in a known room now gets 403.
  - A URL event-ID mismatch now gives 400 on the direct path; the worker path still gives 403.
- **FED-7:** the EDU rate limit is not weighted by fan-out.
- **AUTH-1:**
  - The in-memory audit window is 1024 rows.
  - Safety reports are read from the DB (limit 1000).
  - The PostgreSQL window ordering uses `ctid`, which assumes an append-only table.
  - `audit_log` has no retention policy.
  - `login.rejected` is not rate-capped; it is only throttled per IP.
- **CSAZ-3:**
  - Unread and notification counts are not filtered (they leak counts, not content).
  - Backfilled events sort after joins, so rule 3 can hide them.
  - `/event` without read access still returns 403, not 404.
  - On `/members`, `membership` and `not_membership` combine as AND (pre-existing).
- **HTTP-2:**
  - Appservice, identity-server and policy-server outbound calls are not under the budget.
  - `keys/query` and `keys/claim` still use the 60 s `remote_timeout`.
  - The worker margin has no test.
- **ISO-1:** a thread that already exists before Landlock is not covered on older
  kernels; the ordering rule is the protection. The real worker binary under seccomp is
  not exercised in this container (root).
- **Formatting:** the installed clang-format is 18 and differs from the project's pinned
  version on trailing return types. Agents formatted only their own lines. Run the
  project's formatter check before the PR.

## Environment notes for this container (not part of the product)

- **Build tools:** meson came from pip. `libsodium-dev`, `libpq-dev`,
  `libcurl4-openssl-dev`, `libsqlite3-dev`, `postgresql` and `ccache` came from apt.
- **Subprojects:** sqlite.org and GitHub archive downloads are blocked by the proxy.
  Configure with
  `CC="ccache clang" CXX="ccache clang++" meson setup build -Dbuild_tests=true --wrap-mode=default --force-fallback-for=yyjson,catch2`
  after `git clone --branch 0.12.0 https://github.com/ibireme/yyjson subprojects/yyjson-0.12.0`
  (then copy in `subprojects/packagefiles/yyjson/meson.build`) and
  `git clone --branch v3.14.0 https://github.com/catchorg/Catch2 subprojects/Catch2-3.14.0`.
- **Proxy variables:** the container sets `HTTPS_PROXY` and related variables, which
  libcurl honours. Run the test binaries under
  `env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy`,
  or TLS-mock tests fail spuriously.
- **meson test timeout:** under load, `meson test` kills the three big Catch2 binaries at
  its 600 s timeout. Run them directly.
- **PostgreSQL:** `service postgresql start`, then
  `MEROVINGIAN_TEST_POSTGRESQL_URI=postgresql://merov:merov@127.0.0.1:5432/merov_test`
  (role `merov` is a superuser).
- **Usage limits:** they interrupted the session repeatedly. Work one area at a time,
  commit early, and push the working branch often.
