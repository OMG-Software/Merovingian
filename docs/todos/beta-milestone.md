# Beta Milestone — Open Items

Beta means the homeserver has broad Matrix v1.18 behavior coverage, can survive
realistic operator testing, and can federate with selected remote homeservers in
a non-production environment.

## Done

- ~~Promote remaining endpoint behavior from `partial` to `spec-covered` with
  conformance fixtures.~~ Client-server and federation endpoints promoted to
  `spec-covered`; federation join/leave/invite/knock/backfill, outbound
  delivery, receipts, user directory, and key rotation covered. The final
  event-graph gap — state-at-event reconstruction for `/state` and
  `/state_ids` — is now implemented and conformance-tested.
- ~~Add live PostgreSQL integration tests that cover transaction rollback,
  migration ordering, and role-grant failures.~~ Covered by the
  `postgres-integration` workflow and the persistence integration suite
  (rollback, savepoint, migration ordering, role-grant separation, concurrency
  isolation).
- ~~Wire live media remote-fetch transport and replace thumbnail metadata with
  real image resampling output.~~ Remote-fetch transport + server discovery is
  wired in `media_service.cpp`; thumbnails are now genuinely resampled by the
  sandboxed, out-of-process `merovingian-thumbnail-worker` (PNG/JPEG via
  libpng/libjpeg-turbo), with graceful fallback to original bytes when codecs
  are unavailable.
- ~~Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability.~~ `GET
  /_merovingian/admin/metrics` now emits Prometheus text exposition with stable
  `# HELP` / `# TYPE` metadata and bounded runtime counters/gauges; admin
  observability endpoints return `X-Merovingian-Request-Id` and `Traceparent`
  headers; local request diagnostics carry `request_id`, `trace_id`, and
  `span_id`; and the contract is documented in `docs/observability-audit.md`.
- ~~Add policy server transport integration and richer moderation workflows.~~
  Trust-safety policy transport is now driven by
  `security.trust_safety.policy_server_*`; admin review decisions persist live
  `policy_rules`; and admins can list, upsert, and delete policy rules through
  the client-server admin safety routes.

## Remaining

- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers. (Only Linux, Fedora, and FreeBSD CI jobs exist;
  OpenBSD/NetBSD appear only as release packaging artifacts.)
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests. (Only `fuzz_canonicaljson` and `fuzz_http_request` targets
  exist today.)
