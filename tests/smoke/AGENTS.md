# tests/smoke/ — Smoke Tests

Fast, shallow tests that verify the server starts and responds to basic requests.
They are the first line of defence: if smoke tests fail, nothing else matters.

## Purpose

Smoke tests check that:
- The server binary starts without crashing
- The HTTP listener accepts connections
- `/_matrix/client/versions` returns a valid response
- The database migration completes cleanly

They do **not** test correctness — that is covered by unit and conformance tests.

## Rules

- Smoke tests must complete in under 5 seconds on CI hardware.
- Smoke tests must not require external services (no PostgreSQL, no remote network).
- Use SQLite in-memory or a temporary file database.
- A smoke test that is slow or flaky is worse than no smoke test — delete it and write a unit test instead.

## Triggering

Smoke tests run as part of `python build.py` via `local_smoke_flow.cpp` in `src/homeserver/`.
They are also runnable standalone via the built binary with the `--smoke` flag.
