# Production v1.0.0 — Open Items

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

- ~~Keep real listener coverage in CI and prove the server serves requests until
  stopped by the service manager.~~ Closed (0.12.1): audited the existing
  `test_server_startup_hardening_flow.cpp` binary-spawn test and found it only
  proved "stays alive and shuts down", never actually served a request — and
  that in every existing CI job it WARN-skipped before reaching even that,
  because the runtime hardening self-check can only reach `ready=true` on a
  hardened-profile build (debug builds lack `_FORTIFY_SOURCE`) run by a
  process holding `CAP_SETPCAP` (root containers fail the privilege-drop
  check instead), a combination no existing job satisfied. Fixed by: (1)
  adding a real HTTP GET over a real TCP socket against the spawned process's
  client listener, asserting a genuine 200 from `/_matrix/client/versions`,
  plus a post-shutdown connect-refused check, to the scenario itself; (2) a
  new `ubuntu-hardened-listener-coverage` CI job (`.github/workflows/ci.yml`)
  that builds the `hardened` profile and grants the built `merovingian-server`
  binary `CAP_SETPCAP` via `sudo setcap` (GitHub-hosted runners have
  passwordless sudo) so the scenario actually reaches the live-serving
  assertions instead of skipping. Verified locally: a `--profile hardened`
  build resolved every self-check blocker except capability-bounding (which
  needs `CAP_SETPCAP`, unavailable in the local sandbox used to verify this
  work — the `setcap` grant itself was not re-verified end-to-end outside
  that sandbox; if it does not work as expected on a GitHub-hosted runner the
  scenario will WARN-skip exactly as before, not silently pass).
- ~~Require configured TLS with validated certificate and private-key files for
  public listeners; keep loopback cleartext available for reverse-proxy
  deployments.~~ Implemented with explicit `reverse_proxy` declaration.
- Complete full Matrix v1.19 conformance, persistence, endpoint coverage, and
  production-grade rate limiting for client-server routes.
- ~~Store access tokens only as versioned cryptographic hashes generated from
  LibSodium CSPRNG output.~~ Implemented: access and refresh tokens are
  persisted as domain-separated BLAKE2b digests (`token-hash:v2`/`v3`/`v4`),
  master-key-derived when a master key is configured. See
  [`docs/auth-identity.md`](../auth-identity.md).
- ~~Store passwords only with LibSodium Argon2id password hashes.~~
  Implemented: `crypto_pwhash_str`/`crypto_pwhash_str_verify` (Argon2id) is
  used for account passwords and registration tokens.
- ~~Enforce PostgreSQL transaction coverage, migration coverage, and role
  grants against real temporary databases.~~ The CI-level coverage this
  bullet describes was already closed before this pass:
  `.github/workflows/postgres-integration.yml` provisions real
  `merovingian_migration`/`merovingian_runtime` roles against a live
  PostgreSQL 16 service container and
  `tests/integration/test_postgresql_persistence_flow.cpp` proves transaction
  rollback, migration ordering, and that a runtime-role session is denied
  DDL. **Related packaging gap found and partially closed (0.12.1):**
  `packaging/` provisioned no PostgreSQL roles at all for real deployments —
  added `packaging/postgresql/provision-roles.sql`, the same pattern CI
  already proves, for operators to run. **Still open:** nothing in the live
  startup path actually calls `set_postgresql_role()` —
  `merovingian-db-migrate` never connects to a database (it only prints an
  offline plan) and `bootstrap_local_database()` always applies migrations
  automatically through the same connection/role that then serves runtime
  traffic. See `docs/database-persistence.md` "Next starting points" for the
  precise remaining wiring.
- ~~Fail closed when required production hardening controls are unavailable.~~
  Closed (0.12.1): found the actual fail-open gap — not in
  `hardening_self_check.cpp` (already strictly fail-closed: every check must
  report `enabled`, `unknown` blocks same as `disabled`) but in
  `apply_worker_hardening()` (`src/platform/runtime_hardening.cpp`), which on
  every non-Linux platform unconditionally returned `accept()` regardless of
  whether the operator had requested worker hardening
  (`federation.worker.apply_hardening=true`, the production default) — the
  federation worker would log "runtime hardening applied (seccomp filter
  active)" and start handling untrusted federation traffic completely
  unsandboxed on FreeBSD/OpenBSD/NetBSD, with zero test coverage of this
  function anywhere in the suite. Now returns a fail-closed rejection
  (`worker_hardening_unavailable_decision()`) naming the unavailable controls
  and the `federation.worker.apply_hardening=false` escape hatch; the worker
  process refuses to start rather than run unsandboxed, so the
  `WorkerSupervisor` sees a failing child and federation degrades to 503
  instead of ever accepting unsandboxed traffic. `MEROVINGIAN_TEST_DISABLE_HARDENING`
  is unaffected (a separate escape hatch, unrelated to this function).
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- ~~Add signed release artifacts, reproducible builds, dependency pinning policy,
  license review, provenance, and artifact signatures.~~ Implemented in 0.10.38:
  GPG `.asc` signatures on tarballs and packages, SLSA provenance, SBOM and
  license-summary artifacts, immutable `[wrap-file]` dependency pinning with
  SHA-256 hashes, and byte-for-byte reproducible static Linux tarball
  verification.
- ~~Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and GPG signatures
  in release notes.~~ Closed (0.12.1): checksums and GPG signatures were
  already in the published release notes; added
  `scripts/collect-release-evidence.sh`, run per-platform in
  `.github/workflows/release.yml`, which records the actual compiler version,
  confirms link-time hardening flags landed via `scripts/check-elf-hardening.sh`,
  lists pinned dependency versions from `subprojects/*.wrap`, summarizes the
  test log's Ok/Fail/Timeout counts, and lists the mandatory fuzz target
  names — folded into the published release notes by `publish-alpha-release`
  alongside the existing checksums. Sanitizer logs are cross-referenced to
  the separate `sanitizers.yml` workflow run rather than duplicated (this
  release build does not itself run under a sanitizer).
- Run Complement against CI; add property, load, and chaos tests to lift the
  fuzzing-and-conformance capability off the `integrated` rung. **Audited
  (0.12.1), not implemented — out of budget for this pass:** `tests/fixtures/complement/`
  is this project's own lightweight JSON-fixture flow test, not the upstream
  `matrix-org/complement` Go suite this bullet means. A root `Dockerfile`
  exists but is not Complement-compatible (no `SERVER_NAME`-driven config, no
  federation TLS via Complement's CA, no fixed ports); there is no Go
  toolchain, blueprint registration, or CI wiring anywhere in the repo. This
  remains the largest single piece of unstarted work in this charter.

## Release-blocking functional holes (audited 2026-08-30, 0.12.1 branch)

These outrank the gate list in severity: they are why the server cannot ship,
not paperwork that must accompany shipping. Recorded after the 0.11.13 review
found the capability ladder overstating readiness — `runtime-wired` measures
spec coverage, not transport efficiency or concurrency.

| Blocker | Current state (verified) | Fix required |
| --- | --- | --- |
| No HTTP keep-alive | **Closed on `feature/release-blockers`** — `src/homeserver/http_server.cpp` now serves persistent HTTP/1.1 connections as sequential request rounds: keep-alive by default for 1.1, `Connection: close` honoured and echoed, 1.0 only on explicit request; each request's body is drained exactly so request boundaries are never lost (pipelining buffered and answered in order, out of scope); idle parking bounded by `server.http.keep_alive_idle_seconds` (default 15) plus a process-wide parked-connection cap `server.http.keep_alive_max_connections` (default 8); the phase-aware `connection_guard` (`connection_should_close`) keeps the slowloris kill for mid-request slow clients while exempting idle parks | Closed — see CHANGELOG 0.12.1 |
| Global runtime lock | **Partially closed, with measurement, on `feature/release-blockers` (0.12.1).** `HomeserverRuntime::mutex` is still held for the whole of every client-server request and every inbound federation transaction — that has not changed. Two real, previously-undiscovered lock-safety bugs were found and fixed by writing regression tests first (`tests/integration/test_request_lock_contention_flow.cpp`): (1) `resolve_policy_server_hook`'s call to `trust_safety.policy_server_url` was fixed for inbound federation in #415/0.11.13, but `register_local_user`, `create_room`, and the media download/thumbnail policy check all called it directly while still holding the lock — an operator with `trust_safety.enabled` inherited a policy server that could freeze registration, room creation, and media reads for every other user. (2) `create_room` self-locks `runtime.mutex` (a `recursive_mutex`, so it stays independently callable); calling it from a handler that already held the lock silently double-locked it, so `NetworkIoUnlock` released only the outer level and the mutex stayed effectively held for the whole "unlocked" network call — **this means 0.11.13's `NetworkIoUnlock` mechanism was incomplete for any call chain with a second, self-locking function on the stack**, not just an oversight in call-site coverage. Both are fixed; see `docs/http-transport.md` "`resolve_policy_server_hook`" and "`NetworkIoUnlock` was incomplete for recursive acquisitions". `join_room`/`leave_room` share `create_room`'s self-locking shape and plausibly the same gap for their own outbound federation calls — **not fixed, not yet confirmed either way**, tracked as separate follow-up work (spawned task, not yet landed). A new opt-in load/soak harness (`tests/integration/test_runtime_lock_soak_flow.cpp`, `build_load_tests`) measured the *general* hot path (concurrent `/sync` long-polls, reads, message sends, and signed inbound federation transactions, `trust_safety` disabled) before and after this change over a real 20 s run: throughput and p50/p95/p99 latency for reads (~374–385 req/s, p50 ~7 ms, p95 ~25–26 ms), sends (~469–478 req/s, p50 ~7 ms, p95 ~21–22 ms), and federation transactions (~204–208 req/s, p50 ~6–7 ms, p95 ~23 ms — capped by the federation per-origin transaction rate limiter, not lock contention) were statistically indistinguishable before and after. **This is expected, not a null result to be alarmed by**: neither fix touches that hot path (`trust_safety` is off by default and room creation is not in the harness's timed phase), so the evidence does not show a general-throughput case for narrowing sync/read/send/federation further, and none was attempted. The harness also recorded a `/sync` long-poll anomaly (occasional ~20 s stalls) present *symmetrically* in both the before and after runs — not attributable to this change, not yet root-caused, noted for follow-up. | Confirm (or fix) the `join_room`/`leave_room` self-locking gap the same way `create_room` was fixed, each with its own regression coverage first. Root-cause the `/sync` stall anomaly the load harness surfaced. Re-run the harness after either lands. No further narrowing of the general client-server/federation hot path is justified by the evidence collected so far. |
| Rate limiting not production-grade | **Closed on `feature/release-blockers`** — every client-server route is classified into one of six explicit tiers in `http::rate_limit_tier_for()` (`auth_sensitive`, `media`, `sync`, `federation`, `admin`, `generic`) with per-endpoint accounting; unauthenticated routes are bucketed per remote IP and the credential/enumeration surface resolves to the tighter `auth_sensitive` tier rather than the generic fallback; operators override per-prefix (`client_rate_limits.per_ip.*`), per-tier (`client_rate_limits.tier.<name>`, validated against the tier table so a typo is a parse finding) or the generic default, most-specific-first, and a misconfigured entry at any level fails closed (`invalid_policy`, issue #412). Inbound federation gains a per-X-Matrix-origin cap on non-/send endpoints (`security.federation.per_origin_request_rate`, default 600/min); /send keeps its weighted transaction/PDU/EDU trio so nothing is double-counted. In-memory counters remain by design — operator sign-off recorded in `docs/http-transport.md` | Closed — see CHANGELOG 0.12.1 |
| Application Service API | **`/thirdparty/*` closed on `feature/release-blockers`** — registration files, `as_token`/`hs_token`, `m.login.application_service`, namespace exclusivity, outbound transaction delivery, and all six `GET /_matrix/client/v3/thirdparty/*` third-party lookup routes (backed by outbound `GET /_matrix/app/v1/thirdparty/*` calls, with multi-appservice aggregation and unreachable-appservice degradation) are implemented — see CHANGELOG 0.12.1 and `docs/todos/capability-gaps.md`, "Application service API". **Still open:** the outbound `GET /_matrix/app/v1/users/{userId}` / `/rooms/{roomAlias}` query hooks exist but are not invoked from any local-miss call site, so an unknown user/alias is never resolved by asking the owning appservice | User/room query hooks wired to their local-miss call sites |
| SSO login | `m.login.sso` not advertised; `GET /_matrix/client/v3/login/sso/redirect` unrouted. Password and token login only | SSO login flow routed and advertised |
| Push not production-ready | Delivery-side caps only (128 tasks, 10 pushers/recipient); no per-user pusher *registration* cap; no gateway retry/backoff (spec SHOULD); email pushers accepted and persisted but silently never delivered | Registration-side cap, retry/backoff, and fail-loud handling of unsupported pusher kinds |
| `/messages` state divergence | Returns the room's *current* full state rather than chunk-relevant lazy-loaded state (documented divergence, deliberately not fixed alongside `/context` in 0.11.11) | Chunk-relevance-filtered state for lazy-loading |
| `/search` at scale | In-memory bounded scan over `PersistentStore::events`, joined-rooms-only scope, substring match (no index) | Scale decision: a real index or a recorded production sign-off on the bounded scan |

Of the gate list above, listener CI coverage, fail-closed hardening, mandatory
fuzz execution, and release evidence are now closed as of 0.12.1 (see the
struck-through bullets above). Still blocking the v1.0.0 tag: PostgreSQL
live-role wiring (packaging provisioning landed; the runtime connection path
does not yet `SET ROLE`), config-profile capability-gate naming, and
Complement/property/load/chaos conformance — plus every row in the functional-
holes table above other than HTTP keep-alive.
