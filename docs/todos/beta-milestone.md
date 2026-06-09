# Beta Milestone — Open Items

Beta means the homeserver has broad Matrix v1.18 behavior coverage, can survive
realistic operator testing, and can federate with selected remote homeservers in
a non-production environment.

- Promote remaining endpoint behavior from `partial` to `spec-covered` with
  conformance fixtures.
- Add live PostgreSQL integration tests that cover transaction rollback,
  migration ordering, and role-grant failures.
- Wire live media remote-fetch transport and server discovery into the
  repository remote-ingest boundary, then replace thumbnail metadata with real
  image resampling output.
- Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability.
- Add policy server transport integration, durable policy-rule management, and
  richer moderation workflows.
- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers.
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests.
