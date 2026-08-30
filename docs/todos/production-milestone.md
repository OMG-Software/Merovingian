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
