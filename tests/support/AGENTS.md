# tests/support/ — Test Support Helpers

Shared test utilities used across unit, conformance, and integration tests.

## Contents

| File | Purpose |
|---|---|
| `json_test_support.hpp` | JSON assertion helpers: `require_json_key()`, `parse_or_fail()` |
| `master_key.hpp` | Deterministic Ed25519 key pair for signing in tests; do not use in production |
| `registration_token.hpp` | Generates registration tokens for test users without going through the full UIAA flow |
| `temp_directory.hpp` | Fallback-aware temporary-directory helper for test scratch files |
| `tls_mock_server.hpp` | Self-signed certificate generation plus one-shot and path-dispatching local TLS servers, for tests that need a real HTTPS peer (e.g. a mock identity server) |

## Rules

- **`master_key.hpp` is for tests only.** The key material is deterministic (fixed seed) and
  must never be used in a non-test binary. The file includes a `static_assert` that fires
  if `MEROVINGIAN_TEST_BUILD` is not defined.
- Add helpers here only when they are used by **two or more** test files. Single-use helpers
  belong in an anonymous namespace in the test file that uses them.
- Helpers must not start a database, server, or any I/O — they are pure utilities.
  Any helper that requires I/O belongs in `tests/integration/` as a fixture class.
- **Exception — `tls_mock_server.hpp`.** It writes a temp certificate and accepts real
  loopback TLS connections, so it breaks the no-I/O rule. It lives here because a
  `tests/integration/` fixture is not reachable from `tests/conformance/`, and both suites
  need the same mock HTTPS peer. Keep the exception to this file: any new I/O helper used
  by only one suite still belongs in that suite's directory.
