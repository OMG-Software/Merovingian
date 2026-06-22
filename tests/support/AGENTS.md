# tests/support/ — Test Support Helpers

Shared test utilities used across unit, conformance, and integration tests.

## Contents

| File | Purpose |
|---|---|
| `json_test_support.hpp` | JSON assertion helpers: `require_json_key()`, `parse_or_fail()` |
| `master_key.hpp` | Deterministic Ed25519 key pair for signing in tests; do not use in production |
| `registration_token.hpp` | Generates registration tokens for test users without going through the full UIAA flow |

## Rules

- **`master_key.hpp` is for tests only.** The key material is deterministic (fixed seed) and
  must never be used in a non-test binary. The file includes a `static_assert` that fires
  if `MEROVINGIAN_TEST_BUILD` is not defined.
- Add helpers here only when they are used by **two or more** test files. Single-use helpers
  belong in an anonymous namespace in the test file that uses them.
- Helpers must not start a database, server, or any I/O — they are pure utilities.
  Any helper that requires I/O belongs in `tests/integration/` as a fixture class.
