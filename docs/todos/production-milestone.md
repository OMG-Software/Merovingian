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
| No HTTP keep-alive | `src/homeserver/http_server.cpp` appends `Connection: close` to every response — a full TLS handshake per request for every client | Persistent HTTP/1.1 connections with idle/read timeouts, composed with the existing `connection_guard` slowloris policy and body-size caps |
| Global runtime lock | `HomeserverRuntime::mutex` is held for the whole of every client-server request and every inbound federation transaction (`src/homeserver/AGENTS.md`); 0.11.13 released only the outbound-call offenders via `NetworkIoUnlock` | Narrow the critical section for hot paths and produce load/soak evidence that the remaining critical section holds under concurrency |
| Rate limiting not production-grade | Per-endpoint accounting missing; no remote-IP buckets for unauthenticated routes; no operator-tunable policy overrides (in-memory counters remain by design — operator sign-off recorded in `docs/http-transport.md`) | Per-endpoint accounting, remote-IP buckets for unauthenticated routes, operator-tunable overrides |
| Application Service API | Entire API unimplemented — no `as_token`/`hs_token`, no registration files, no `/_matrix/app/v1/*` outbound calls, no `m.login.application_service`, no namespace exclusivity; `/_matrix/client/v3/thirdparty/protocols` returns `{}` as a placeholder. No bridges or bots can operate | Full API: registration files, token handling, login type, `?user_id=` masquerading, outbound transactions with at-least-once delivery, user/room query hooks, `/thirdparty/*` |
| SSO login | `m.login.sso` not advertised; `GET /_matrix/client/v3/login/sso/redirect` unrouted. Password and token login only | SSO login flow routed and advertised |
| Push not production-ready | Delivery-side caps only (128 tasks, 10 pushers/recipient); no per-user pusher *registration* cap; no gateway retry/backoff (spec SHOULD); email pushers accepted and persisted but silently never delivered | Registration-side cap, retry/backoff, and fail-loud handling of unsupported pusher kinds |
| `/messages` state divergence | Returns the room's *current* full state rather than chunk-relevant lazy-loaded state (documented divergence, deliberately not fixed alongside `/context` in 0.11.11) | Chunk-relevance-filtered state for lazy-loading |
| `/search` at scale | In-memory bounded scan over `PersistentStore::events`, joined-rooms-only scope, substring match (no index) | Scale decision: a real index or a recorded production sign-off on the bounded scan |

The gate list above (listener CI coverage, PostgreSQL real-temp-DB enforcement,
fail-closed hardening, config-profile capability gates, mandatory fuzz
execution, release evidence) is unchanged and still blocks the v1.0.0 tag.
