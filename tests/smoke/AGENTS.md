# tests/smoke/ — Smoke Tests

Fast, shallow tests that verify the server starts and responds to basic requests.
They are the first line of defence: if smoke tests fail, nothing else matters.

## Purpose

Smoke tests check that:
- The server binary starts without crashing
- `--help`, `--version`, `--dry-run`, `--check-config`, and `--plan-config-reload`
  behave as documented from the CLI
- Config validation and the database migration path complete cleanly

They do **not** exercise a live HTTP listener — that end-to-end path (real TCP/TLS
listener, `/_matrix/client/versions`) is covered by
`tests/integration/test_http_server_listener_flow.cpp`, and the full
vertical-slice startup flow (`run_local_smoke_flow` /
`local_smoke_flow.cpp` in `src/homeserver/`) is exercised from
`tests/integration/test_homeserver_vertical_slice_flow.cpp`, not from this
directory. Smoke tests here do **not** test correctness — that is covered by
unit and conformance tests.

## Rules

- Smoke tests must complete in under 5 seconds on CI hardware.
- Smoke tests must not require external services (no PostgreSQL, no remote network).
- Use SQLite in-memory or a temporary file database.
- A smoke test that is slow or flaky is worse than no smoke test — delete it and write a unit test instead.

## Triggering

Smoke tests are shell-script probes of CLI behavior registered in
`tests/smoke/meson.build` and run as part of `python build.py`. There is no
`--smoke` binary flag; the server binary does not accept one.
