# Production v1.0.0 — Open Items

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

- Keep real listener coverage in CI and prove the server serves requests until
  stopped by the service manager.
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
- Enforce PostgreSQL transaction coverage, migration coverage, and role grants
  against real temporary databases.
- Fail closed when required production hardening controls are unavailable.
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- ~~Add signed release artifacts, reproducible builds, dependency pinning policy,
  license review, provenance, and artifact signatures.~~ Implemented in 0.10.38:
  GPG `.asc` signatures on tarballs and packages, SLSA provenance, SBOM and
  license-summary artifacts, immutable `[wrap-file]` dependency pinning with
  SHA-256 hashes, and byte-for-byte reproducible static Linux tarball
  verification.
- Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and GPG signatures
  in release notes.
- Run Complement against CI; add property, load, and chaos tests to lift the
  fuzzing-and-conformance capability off the `integrated` rung.

## Release-blocking functional holes (audited 2026-08-30, 0.12.1 branch)

These outrank the gate list in severity: they are why the server cannot ship,
not paperwork that must accompany shipping. Recorded after the 0.11.13 review
found the capability ladder overstating readiness — `runtime-wired` measures
spec coverage, not transport efficiency or concurrency.

| Blocker | Current state (verified) | Fix required |
| --- | --- | --- |
| No HTTP keep-alive | **Closed on `feature/release-blockers`** — `src/homeserver/http_server.cpp` now serves persistent HTTP/1.1 connections as sequential request rounds: keep-alive by default for 1.1, `Connection: close` honoured and echoed, 1.0 only on explicit request; each request's body is drained exactly so request boundaries are never lost (pipelining buffered and answered in order, out of scope); idle parking bounded by `server.http.keep_alive_idle_seconds` (default 15) plus a process-wide parked-connection cap `server.http.keep_alive_max_connections` (default 8); the phase-aware `connection_guard` (`connection_should_close`) keeps the slowloris kill for mid-request slow clients while exempting idle parks | Closed — see CHANGELOG 0.12.1 |
| Global runtime lock | `HomeserverRuntime::mutex` is held for the whole of every client-server request and every inbound federation transaction (`src/homeserver/AGENTS.md`); 0.11.13 released only the outbound-call offenders via `NetworkIoUnlock` | Narrow the critical section for hot paths and produce load/soak evidence that the remaining critical section holds under concurrency |
| Rate limiting not production-grade | **Closed on `feature/release-blockers`** — every client-server route is classified into one of six explicit tiers in `http::rate_limit_tier_for()` (`auth_sensitive`, `media`, `sync`, `federation`, `admin`, `generic`) with per-endpoint accounting; unauthenticated routes are bucketed per remote IP and the credential/enumeration surface resolves to the tighter `auth_sensitive` tier rather than the generic fallback; operators override per-prefix (`client_rate_limits.per_ip.*`), per-tier (`client_rate_limits.tier.<name>`, validated against the tier table so a typo is a parse finding) or the generic default, most-specific-first, and a misconfigured entry at any level fails closed (`invalid_policy`, issue #412). Inbound federation gains a per-X-Matrix-origin cap on non-/send endpoints (`security.federation.per_origin_request_rate`, default 600/min); /send keeps its weighted transaction/PDU/EDU trio so nothing is double-counted. In-memory counters remain by design — operator sign-off recorded in `docs/http-transport.md` | Closed — see CHANGELOG 0.12.1 |
| Application Service API | **`/thirdparty/*` closed on `feature/release-blockers`** — registration files, `as_token`/`hs_token`, `m.login.application_service`, namespace exclusivity, outbound transaction delivery, and all six `GET /_matrix/client/v3/thirdparty/*` third-party lookup routes (backed by outbound `GET /_matrix/app/v1/thirdparty/*` calls, with multi-appservice aggregation and unreachable-appservice degradation) are implemented — see CHANGELOG 0.12.1 and `docs/todos/capability-gaps.md`, "Application service API". **Still open:** the outbound `GET /_matrix/app/v1/users/{userId}` / `/rooms/{roomAlias}` query hooks exist but are not invoked from any local-miss call site, so an unknown user/alias is never resolved by asking the owning appservice | User/room query hooks wired to their local-miss call sites |
| SSO login | `m.login.sso` not advertised; `GET /_matrix/client/v3/login/sso/redirect` unrouted. Password and token login only | SSO login flow routed and advertised |
| Push not production-ready | Delivery-side caps only (128 tasks, 10 pushers/recipient); no per-user pusher *registration* cap; no gateway retry/backoff (spec SHOULD); email pushers accepted and persisted but silently never delivered | Registration-side cap, retry/backoff, and fail-loud handling of unsupported pusher kinds |
| `/messages` state divergence | Returns the room's *current* full state rather than chunk-relevant lazy-loaded state (documented divergence, deliberately not fixed alongside `/context` in 0.11.11) | Chunk-relevance-filtered state for lazy-loading |
| `/search` at scale | In-memory bounded scan over `PersistentStore::events`, joined-rooms-only scope, substring match (no index) | Scale decision: a real index or a recorded production sign-off on the bounded scan |

The gate list above (listener CI coverage, PostgreSQL real-temp-DB enforcement,
fail-closed hardening, config-profile capability gates, mandatory fuzz
execution, release evidence) is unchanged and still blocks the v1.0.0 tag.
