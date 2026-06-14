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

## Remaining

- Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability. (Only a `/admin/metrics`
  endpoint exists today; no trace/span correlation.)
- Add policy server transport integration and richer moderation workflows.
  (Durable policy-rule persistence via the `policy_rules` table already exists;
  the policy engine still evaluates a pre-populated `PolicyServerHook` with no
  HTTP transport that contacts a remote policy server.)
- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers. (Only Linux, Fedora, and FreeBSD CI jobs exist;
  OpenBSD/NetBSD appear only as release packaging artifacts.)
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests. (Only `fuzz_canonicaljson` and `fuzz_http_request` targets
  exist today.)
