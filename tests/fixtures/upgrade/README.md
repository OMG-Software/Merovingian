# Cross-release database upgrade fixtures

Each subdirectory holds a database that was really written by an OLD Merovingian
release, so a test can prove the current server opens, migrates and serves it.
Nothing in these files is hand-written: the old `merovingian-server` produced
every row through its real HTTP Client-Server API (ADR-0216).

## No fixture until 1.1

There is none today. In 0.12.47 every pre-1.0 migration collapsed into one v1
schema (ADR-0224), so no database a pre-1.0 release wrote can be opened any more,
and the 0.11.13 fixture that stood here was removed with the chain it tested.
Upgrade compatibility is promised from 1.0.0. When the 1.1 series starts, the
last 1.0.x release writes the next fixture into `tests/fixtures/upgrade/<release>/`,
and `tests/integration/test_database_upgrade_flow.cpp` gains the scenarios that
open, migrate and serve it.

## Generating

Run inside Linux or WSL as an unprivileged user, with git, meson, ninja, clang++,
the PostgreSQL server binaries, and python3 with the `cryptography` package
(required: it signs the uploaded device keys, and generation fails without it):

```sh
python3 scripts/generate_upgrade_fixture.py \
    <release-commit> tests/fixtures/upgrade/<release> \
    --checkout-dir ~/merovingian-<release>
```

The script builds the old commit in a Linux-native checkout (never on a Windows
mount), runs it twice (SQLite, then a throwaway PostgreSQL cluster it creates and
removes itself), checks both results, and writes three files:

| File | Content |
|---|---|
| `merovingian.sqlite3` | SQLite database after a clean `SIGTERM` shutdown, WAL checkpointed, single file |
| `postgresql.sql` | `pg_dump --no-owner --no-privileges --no-comments --column-inserts`, no `COPY`, no psql meta-commands, executable statement by statement through `PQexec` |
| `manifest.json` | Master key (hex), registration token, and per backend the users, tokens, room IDs, event IDs, media, account data and pusher the test should find after the upgrade |

Every run generates new random IDs, tokens and master key, so a regeneration
changes all three files together and the test must always read them from the
manifest. Never regenerate a fixture with current code: it is evidence only
because the old release wrote it.
