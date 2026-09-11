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

## Standalone E2EE smoke-test clients (not Meson tests)

`tests/matrix_e2ee_two_user_test.py` and `tests/matrix_e2ee_windows_test.py` are
manually-invoked Python smoke-test clients, not Catch2 tests — **neither is
registered in any `meson.build`** (confirmed by grep), so `meson test` never
runs them; run them directly against a live `merovingian-server`.

- `matrix_e2ee_two_user_test.py` registers two users via `matrix-nio[e2e]`
  (requires `pip install "matrix-nio[e2e]" aiofiles`, which pulls in native
  libolm), creates an `m.megolm.v1.aes-sha2`-encrypted DM, has each side
  pin/verify the other's device out-of-band, sends encrypted messages both
  ways, asserts each side decrypts the other's message, then logs both out.
  Key options: `--homeserver` (required), `--registration-token`,
  `--use-existing`, `--store-root`, `--keep-store`, `--timeout`, `--insecure`,
  `--log-level`.
- `matrix_e2ee_windows_test.py` is the Windows-native equivalent: native
  libolm is not a reliable install path on Windows, so this script generates
  a throwaway Node.js project and drives `matrix-js-sdk`'s Rust-Crypto WASM
  backend (via `npm install`) for the real Olm/Megolm crypto, then runs the
  same register/invite/join/encrypted-send/decrypt/logout flow as a child
  process. Requires Node.js LTS 20+/22+ and `npm` on `PATH`. Key options:
  `--homeserver` (required), `--registration-token`, `--use-existing`,
  `--workdir`, `--keep-workdir`, `--skip-npm-install`, `--timeout`,
  `--log-level`, `--matrix-js-sdk-version`.

## Sanitizers

Integration tests run under ASan/UBSan (`-Db_sanitize=address,undefined`) and TSan
(`-Db_sanitize=thread`) in CI. Write tests so they are clean under both.
