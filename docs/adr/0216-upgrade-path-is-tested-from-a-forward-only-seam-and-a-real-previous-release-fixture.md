# The upgrade path is tested from a forward-only schema seam and a database the previous release wrote

* Status: accepted
* Date: 2026-10-23

Technical Story: production milestone blocker "No tested upgrade path across releases" (0.12.42)

## Context and Problem Statement

Both stores migrate a database whose schema version is older than the build's
(`apply_pending_migrations` in `sqlite_store.cpp` and `postgresql_store.cpp`). A fresh
database takes that path from the v1 bootstrap, but with every table empty, and a restart
reopens a database the same binary just wrote, so the path never runs at all. Nothing
showed that rows an older release wrote survive the migrations and are served afterwards.
For a 1.0.0 that promises stable upgrades, that is the larger operational risk.

How should the project test that a database the previous minor series wrote opens,
migrates and serves under a release candidate?

## Decision Drivers

* The evidence must come from data the old release wrote, not from what this project
  believes it wrote. Column shapes are in the migrations; value formats (token hashes,
  encrypted secrets, JSON columns) are only in the old code.
* Individual migrations need data-preservation coverage too, with no old binary to hand.
* There are no per-release git tags to build an old release from in CI (only `latest`).
* CI time: building two releases on every pull request doubles the slowest job.

## Considered Options

* A forward-only seam and synthetic rows only
* Committed fixtures written by the previous release only
* Both: the seam for synthetic per-version tests, and committed fixtures for the real thing
* A CI job that builds the previous release on every run and writes a fresh database

## Decision Outcome

Chosen option: "Both", because the two answer different questions and neither covers the
other's. The seam (`migrate_sqlite_schema_to`, `migrate_postgresql_schema_to`) builds a
schema at any older version and stops, so tests can put that version's rows in it and
start the current runtime on it, for every version, on both backends. The fixtures under
`tests/fixtures/upgrade/<release>/` were written over HTTP by the last release of the
previous minor series (0.11.13, schema v11), so they carry that release's real formats;
the candidate must open, migrate and serve them.

The seam is public API rather than a test-only header. It only moves a schema forward,
refuses a version this build does not know before touching the database, and refuses a
schema already past the target, so the worst a misuse can do is leave a database at an
older version that the next open completes. Both migration runners also refuse a state
already past the target, so a racing process that migrated further can never turn a call
into a downgrade plan.

Rules this sets for future work:

* **Never regenerate a fixture with current code.** A fixture is evidence only because
  the old release wrote it. `scripts/generate_upgrade_fixture.py` builds the named old
  commit; regenerate only when moving to a new previous release.
* **When a minor series starts**, replace the fixture with one from the last release of the
  series before it (generated from that release's commit), and move
  `previous_series_schema_version` and `previous_series_fixture_release` in
  `tests/integration/test_database_upgrade_flow.cpp` to that release.
* A synthetic row in a test is written in the column shape of the version it is seeded
  at, never the current shape.

### Before 1.0.0, and at it

No deployment runs this software yet, and the owner intends to collapse every migration
into one initial schema when 1.0.0 is released. Two consequences follow:

* Upgrade compatibility is promised from 1.0.0 onward, not between pre-1.0 releases. A
  pre-1.0 behaviour change that existing data does not carry over is acceptable when the
  owner says so. The first instance is the room directory: 0.11 listed every room whose
  join rule was `public` and stored no choice to publish, so after migration 018
  (`rooms.directory_public`, default `false`) an upgraded room is unlisted until a room
  administrator publishes it again. The owner declined a backfill (2026-10-23), and the
  fixture test does not assert the directory.
* When the migrations collapse, a pre-1.0 database can no longer be opened, so the 0.11.13
  fixture and its scenarios are removed in that change, and `previous_series_*` waits for
  the last 1.0.x release, whose fixture is added when 1.1 starts. The seam, the generator
  and the synthetic scenarios stay.

The 0.11.13 fixture still earns its place until then. Running it found two defects that
affect every deployment, not only upgrades: the PostgreSQL store never loaded `profiles`,
so every displayname and avatar vanished at each restart, and both stores read the
migration ledger in text order (`'10'` before `'9'`), so a reloaded ledger's last entry was
not the newest migration.

### Positive Consequences

* The milestone blocker has an executable check on both backends in the normal suite
  (PostgreSQL scenarios run in the `postgres-integration` workflow).
* A format change that breaks old data (for example, how a token hash or a signing secret
  is stored) fails a test instead of a production upgrade.

### Negative Consequences

* Binary and SQL fixtures live in the repository and must be regenerated, from the old
  commit, once per minor series.
* The fixture tests only show what the previous release's last version wrote; an upgrade
  that skips a whole series is not covered.
* Between the 1.0.0 collapse and the start of 1.1 there is no previous-release fixture.

## Pros and Cons of the Options

### A forward-only seam and synthetic rows only

* Good, because it is self-contained and covers every version.
* Bad, because the rows reflect this project's belief about what the old release wrote.

### Committed fixtures written by the previous release only

* Good, because it is the strongest evidence.
* Bad, because it covers one version and gives no way to test an individual migration.

### A CI job that builds the previous release on every run

* Good, because the old database is always freshly written.
* Bad, because it doubles the build on every pull request, and there are no release tags
  to build from; a fixture written once by the same old commit is equally strong evidence.

## Links

* [docs/database-persistence.md](../database-persistence.md) — migration policy
* [docs/todos/production-milestone.md](../todos/production-milestone.md) — the blocker this closes
