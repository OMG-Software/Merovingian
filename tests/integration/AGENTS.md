# tests/integration/ — Integration / Flow Tests

Integration tests verify end-to-end behavior across module boundaries using real dependencies.
No mocks. Use a real in-process SQLite store or a PostgreSQL test database.

## File naming

`test_<domain>_flow.cpp` — the `_flow` suffix distinguishes these from unit tests.

## What belongs here

- Behaviors that span two or more modules (e.g., auth + database + HTTP)
- Tests that require a live database connection
- Tests that exercise a complete user-visible action end-to-end (register → login → send message → sync)
- Tests that require a listening HTTP server

## What does NOT belong here

- Single-function isolation tests → `tests/unit/`
- Matrix spec MUST/SHOULD verification → `tests/conformance/`
- Live network or remote server tests → use opt-in `build_live_tests=true` and mark clearly

## Structure

Same SCENARIO/GIVEN/WHEN/THEN structure as unit tests. Set up the full server stack or
database fixture in `GIVEN`; trigger the user-visible action in `WHEN`; assert the observable
outcome in `THEN`.

## Live federation tests

`test_live_synapse_federation.cpp` is guarded by the `build_live_tests` Meson option.
Never make standard integration tests depend on external network connectivity.
Default build must pass with no internet access.

## Sanitizers

Integration tests run under ASan/UBSan (`-Db_sanitize=address,undefined`) and TSan
(`-Db_sanitize=thread`) in CI. Write tests so they are clean under both.
