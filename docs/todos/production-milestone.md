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
| Global runtime lock | `HomeserverRuntime::mutex` is held for the whole of every client-server request and every inbound federation transaction (`src/homeserver/AGENTS.md`); 0.11.13 released only the outbound-call offenders via `NetworkIoUnlock` | Narrow the critical section for hot paths and produce load/soak evidence that the remaining critical section holds under concurrency |
| Rate limiting not production-grade | Per-endpoint accounting missing; no remote-IP buckets for unauthenticated routes; no operator-tunable policy overrides (in-memory counters remain by design — operator sign-off recorded in `docs/http-transport.md`) | Per-endpoint accounting, remote-IP buckets for unauthenticated routes, operator-tunable overrides |
| Application Service API | Entire API unimplemented — no `as_token`/`hs_token`, no registration files, no `/_matrix/app/v1/*` outbound calls, no `m.login.application_service`, no namespace exclusivity; `/_matrix/client/v3/thirdparty/protocols` returns `{}` as a placeholder. No bridges or bots can operate | Full API: registration files, token handling, login type, `?user_id=` masquerading, outbound transactions with at-least-once delivery, user/room query hooks, `/thirdparty/*` |
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
