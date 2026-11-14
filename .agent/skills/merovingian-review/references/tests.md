# Reviewing tests

The binding text is [docs/testing-standards.md](../../../../docs/testing-standards.md) and the `tests/*/AGENTS.md`
files. This is the reviewer's cut of them.

## Where a test belongs

| Directory | Belongs | Does not belong |
|---|---|---|
| `tests/unit/` | One module in isolation; pure logic; SQLite only for database behaviour; concurrency scenarios for thread-safe types | Anything that builds a runtime (`start_runtime`, `start_client_server`, `wire_federation_callbacks`) or drives the client-server stack (ADR-0593); spec MUST/SHOULD checks; network |
| `tests/conformance/` | One Matrix v1.19 MUST or SHOULD per scenario, `test_<area>_conformance.cpp` | Internal-structure tests |
| `tests/integration/` | Two or more modules, a live DB, a listening server, full flows, `test_<domain>_flow.cpp`; real dependencies, no mocks | Live internet, except opt-in under `build_live_tests` |
| `tests/fuzz/` | One parser fed raw bytes; asserts no crash or hang only | Correctness |
| `tests/smoke/` | CLI probes under 5 s, no external services | HTTP listeners, correctness |
| Fuzz regression | A SCENARIO in `tests/unit/test_<surface>.cpp` tagged `[fuzz][regression]`, plus the minimised input in `tests/fuzz/corpus/<target>/` | |

Sources: `tests/unit/AGENTS.md#Unit vs. other test directories`, `tests/integration/AGENTS.md#What belongs here`,
`tests/conformance/AGENTS.md#Purpose`, `docs/testing-standards.md#Unit or integration`.

## Required structure (check by hand where no gate does)

- `SCENARIO` with `GIVEN`, `WHEN` and `THEN` in every tier, not only unit. Setup goes in GIVEN, one action in WHEN,
  assertions in THEN. The BDD gate checks only `tests/unit`, and only that the words appear somewhere in the file.
- Tags: unit `[module]` matching the directory; conformance `[conformance]` plus an area tag; fuzz regression
  `[<surface>][fuzz][regression]`. **A scenario that reaches PostgreSQL carries `[postgresql]`.** That tag is the
  whole of what the PostgreSQL CI job runs (ADR-0511). An untagged one skips in CI and passes having tested
  nothing. `tests/tooling/test_ci_run_scope.py` reads only the scenario's own text, so it misses a helper that
  opens the connection.
- Conformance: a citation block above every SCENARIO (Spec, Endpoint/Section, URL into `docs/matrix-v1.19-spec/`,
  the MUST in a sentence). Never weaken, remove or comment out a `REQUIRE`. Never change an expected value
  without citing the spec section. The spec outranks Synapse, Complement and audit reports.
  `tests/conformance/AGENTS.md#Rules — Non-Negotiable`
- Security-sensitive code needs negative paths: invalid input, boundary sizes, and no partial state left on error.
  `tests/unit/AGENTS.md#Security-sensitive code`
- A forged-signature test signs with the **wrong key**. An unsigned input proves only the structural check.
- A thread-safe type needs a concurrency scenario: many threads, a release barrier, a result checked per call. The
  model is the scenario in `tests/unit/test_outbound_client.cpp`.
- Registration: unit and conformance files go in `tests/meson.build` (gated). Integration files go in the
  `integration_tests` source list (**not gated**: check it). A new test binary that registers users needs the
  `crypto_pwhash_str` wrap and `RealPasswordHashCost.cpp` (ADR-0510).
- A new `SKIP()` needs an entry in `tests/expected_skips.json` for every CI job that skips it (ADR-0546).
- A helper goes in `tests/support/` only when two or more files use it.

## Pitfalls that have produced false greens

- **Catch2 assertions are not thread-safe.** Collect results on worker threads, and assert on the main thread.
- **A joinable `std::thread` in scope when a `REQUIRE` fails or a `SKIP` fires calls `std::terminate`**, which kills
  the whole binary. Mock-server threads use `ScopedThreadJoin` or `JoiningThreads`. Never use `std::jthread`.
- **Minimum-cost Argon2 cannot exercise a race** around the hash window. A race scenario holds
  `RealPasswordHashCost` from its first line. `docs/testing-standards.md#Password hashing cost in the test binaries`
- **Blocking `::connect()`** in integration tests hangs on OpenBSD. Use `connect_within`, and bound reads and
  writes.
- **Live PostgreSQL scenarios share one database.** A scenario asserting on all writes uses
  `ScratchPostgresqlDatabase` (ADR-0227). Do not filter statement names to make it pass.
- **TLS test servers** trust the test CA, not a self-signed certificate.
  `docs/testing-standards.md#Live join_room integration tests`
- **`wire_federation_callbacks` after `remote_key_resolver`** overwrites the test double.
- **Timing-dependent scenarios** use `test_frozen_event_clock_ms`, not loops.
- **An older test pinning the old behaviour.** When the change alters a visibility, auth or cap rule, search for
  tests that asserted the old outcome, and run the **full** suite, not only the new tags. Tag-filtered runs have
  been green while older assertions elsewhere failed.
- **Tests that check shape, not content.** A sync test that asserts a field exists does not prove the right events
  are in it.
- **A real-kernel seccomp test that SKIPs** when the filter is wrong hides an allow-all filter. It must fail.
- **A fixture key that expired** made tests reach real hosts. Integration tests must pass with no internet.

## Running and reading

- Build and test with the command the root `AGENTS.md` names. Run it in the background and wait. Read the
  `Ok:`, `Fail:` and `Timeout:` counts from `meson-logs/testlog.txt` in that build directory. A timeout is a
  failure. Lines with a zero count may be omitted.
- The log is evidence only if its modification time is after the build started. A failed compile leaves the
  previous log and the previous binaries in place.
- Prove a scenario ran with a tag filter:
  `python build.py vm --exec ./build-vm/tests/merovingian-unit-tests "[push]"`. `--exec` sets
  `MEROVINGIAN_TEST_DISABLE_HARDENING=1`, which any direct run of a test binary needs. Expect
  `All tests passed (N assertions in M test cases)` with M at least 1. Empty output for a new tag means the binary
  is stale. A zero-byte binary exits 0.
- Binaries and meson timeouts: `merovingian-unit-tests` (600 s), `merovingian-conformance-tests` (900 s),
  `merovingian-integration-tests` (1800 s; 900 s on the BSDs), `merovingian-password-cost-tests`.
- A second suite running on the same machine causes unrelated timeouts. Re-run alone; do not raise the timeout.
- **Fails-if-reverted check:** make a worktree at the base commit, apply only the test changes
  (`git diff <base>...<head> -- tests/ | git apply`), build, run the tag. The new scenario must fail. If it
  passes, it does not test the fix.
- Platform code inside `#if` blocks for BSD is not compiled on Linux. Syntax-check it with
  `-fsyntax-only -U__linux__ -D__FreeBSD__` using the flags from `compile_commands.json`. GCC-only warnings
  (`-Wshadow` on lambda parameters, `-Werror=null-dereference` under LTO) need a GCC build.
