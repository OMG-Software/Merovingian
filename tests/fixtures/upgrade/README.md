# Cross-release database upgrade fixtures

Each subdirectory holds a database that was really written by an OLD Merovingian
release, so a test can prove the current server opens, migrates and serves it.
Nothing in these files is hand-written: the old `merovingian-server` produced
every row through its real HTTP Client-Server API.

## `0.11.13/`

Made from commit `670109767039a2b300c6cce8d7e3300624ba0c5f` (release 0.11.13,
schema version 11, `server.name = example.org`).

| File | Content |
|---|---|
| `merovingian.sqlite3` | SQLite database after a clean `SIGTERM` shutdown, WAL checkpointed, single file |
| `postgresql.sql` | `pg_dump --no-owner --no-privileges --no-comments --column-inserts`, no `COPY`, no psql meta-commands, executable statement by statement through `PQexec` |
| `manifest.json` | Master key (hex), registration token, and per backend the users, tokens, room IDs, event IDs, media, account data and pusher the test should find after the upgrade |

Both backends were produced with the same master key. The server signing key is
stored in `server_signing_keys.secret_key` as a `secretbox:v1:` value encrypted
under that master key, so the master key in the manifest is needed to load it.
Access tokens do not expire (`security.access_token_lifetime_ms=0`), and
`schema_migrations.version` is a TEXT column: cast it before taking `max()`.

Passwords and tokens in the manifest are test values for a test-only fixture.

## Regenerating

Run inside Linux or WSL as an unprivileged user, with git, meson, ninja, clang++,
python3 (the `cryptography` package signs the uploaded device keys) and the
PostgreSQL server binaries installed:

```sh
python3 scripts/generate_upgrade_fixture.py \
    670109767039a2b300c6cce8d7e3300624ba0c5f tests/fixtures/upgrade/0.11.13 \
    --checkout-dir ~/merovingian-0.11.13
```

The script builds the old commit in a Linux-native checkout (never on a Windows
mount), runs it twice (SQLite, then a throwaway PostgreSQL cluster it creates and
removes itself), checks both results, and overwrites the three files. Every run
generates new random IDs, tokens and master key, so a regeneration changes all
three files together and the test must always read them from the manifest.
