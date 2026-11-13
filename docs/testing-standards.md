# Testing Standards

## Mandatory test structure

All tests in The Merovingian must use explicit Given/When/Then structure.

This rule applies to:

- unit tests
- integration tests
- federation tests
- property tests
- fuzz regression tests
- regression suites
- security tests

## Requirements

- Test names must describe observable behavior.
- Setup code is the `Given` phase.
- Trigger/action code is the `When` phase.
- Assertions are the `Then` phase.
- Avoid implementation-detail-oriented naming.
- Prefer one behavioral assertion group per test.
- Security-sensitive code requires negative-path tests.

## Unit or integration

A unit test exercises one module. A scenario that builds a homeserver runtime (`start_runtime`, `start_client_server`,
`wire_federation_callbacks`) or drives the client-server stack (`handle_client_server_request`,
`handle_client_server_http_request`, `run_client_server_flow`) is an integration test, even when it then calls a single
service function: starting a runtime wires config, the store, the signing key and every service. Such scenarios go in
`tests/integration/test_<name>_flow.cpp`; `scripts/check-unit-test-isolation.sh` fails the suite when a file under
`tests/unit/` names one of those functions (ADR-0593). The directory guides, `tests/unit/AGENTS.md` and
`tests/integration/AGENTS.md`, have the rest of the split.

## Concurrency and locking tests

Assert on what a thread holding none of the resource can observe, not on what a
guard reports about itself. A `std::recursive_mutex` answers `try_lock()` with
"yes" to its own owner at any depth, and `std::unique_lock::owns_lock()` is
bookkeeping that a release scope may deliberately leave stale (see
[ADR-0004](adr/0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md)).
Neither distinguishes "the lock is free"
from "one level of it was released" — the distinction three separate
production stalls turned on.

- Probe from another thread and assert on the main thread. Catch2's assertion
  macros are not thread-safe (see "Thread safety tests" in
  `tests/unit/AGENTS.md`).
- Cover the nested case, not only the single-scope one. A primitive that is
  correct in isolation can still be wrong one frame down; that is exactly how a
  defect survived the first round of review on #490.
- Prove a new scenario fails against the unfixed code before trusting it. A
  regression test that passes either way documents nothing.

## Password hashing cost in the test binaries

The unit, conformance and integration binaries hash passwords and registration tokens at libsodium's minimum Argon2id cost
([ADR-0510](adr/0510-the-test-binaries-hash-passwords-at-minimum-cost.md)). `-Wl,--wrap=crypto_pwhash_str` sends the
production code's call to `tests/support/RealPasswordHashCost.cpp`, so no production code changes.

- The override refuses any cost but the one production asks for, so a downgrade in `src/auth/Password.cpp` makes every
  registration and login fail rather than go unnoticed.
- `merovingian-password-cost-tests` is linked without the override and proves what the shipped code does.
- A scenario that needs the hash to take real time holds `merovingian::tests::RealPasswordHashCost` from its first line. That
  means any scenario racing another request against the window in which the runtime lock is released around Argon2id: at
  minimum cost that window is too short for the other thread to land in, and the scenario fails intermittently, or
  passes without exercising the race. Verifying costs whatever the stored hash was made with, so a guard taken after the
  user registered is too late.
- Do not add a new test binary that registers users without the same link argument and support file, unless it exists to
  see the real cost.

## Socket calls in integration tests

Every socket call in an integration test has a deadline, so a server that never
answers fails one scenario instead of holding the whole binary until meson's
timeout kills it. Connect with `merovingian::tests::connect_within`
(`tests/integration/BoundedConnect.hpp`), never a blocking `::connect()`: on
OpenBSD 7.9 a blocking connect to the test's own in-process listener never
returned. Bound reads and writes with `poll` or `SO_RCVTIMEO`/`SO_SNDTIMEO`.

## Live PostgreSQL scenarios

A scenario that reaches PostgreSQL carries the `[postgresql]` tag, because that tag is the whole of what the
`postgres-integration` job runs ([ADR-0511](adr/0511-a-commit-runs-each-workflow-once.md)). `tests/tooling/test_ci_run_scope.py`
checks for it, but it reads the scenario's own text, so it cannot see a helper that opens a connection for the scenario. Without
`MEROVINGIAN_TEST_POSTGRESQL_URI` these scenarios skip, so an untagged one passes in CI having tested nothing.

### Scenarios that need a quiet store

The live PostgreSQL scenarios share one database (`MEROVINGIAN_TEST_POSTGRESQL_URI`),
and a runtime started on it replays the durable queues earlier scenarios left there
(the dispatch worker's `federation_transactions`, the retry job's `deferred_pdus`). Those
background workers then write to the store whenever a retry falls due. A scenario that asserts
on every write the store commits (`enable_statement_capture` and an empty
`captured_statements`), or that needs an empty schema, runs on a database of its own:
`merovingian::tests::ScratchPostgresqlDatabase`
(`tests/integration/ScratchPostgresqlDatabase.hpp`), declared before anything that
connects to it so it is dropped last. Do not narrow the assertion instead, by
filtering statement names, stopping a worker or capturing one thread only: each of
those also hides a write the code under test makes (ADR-0227).

## Live client-server probes

Tests that exercise an authenticated endpoint on a deployed Merovingian server
must be guarded by the build_live_tests option and read a short-lived access
token from an environment variable. They must skip when the token is absent,
never log the token or response content, and use a unique client-controlled
identifier when the endpoint supports one. The Sliding Sync live probe uses
MEROVINGIAN_LIVE_ACCESS_TOKEN.

## Conformance tests

- Matrix conformance and spec-facing tests must cite the exact spec version they
  are pinned to.
- Each conformance test file should carry a prominent comment stating that a
  failure means the implementation must be fixed before the assertion is
  weakened or removed.
- Each scenario should cite the relevant spec URL or section immediately above
  the scenario.
- If a conformance expectation changes, the test comment must cite the newer
  spec section that justifies the change.

## Complement

Complement, the external Matrix homeserver suite, runs against the release
package in the image under `tests/complement/` (ADR-0233). Its rules are in
`tests/complement/AGENTS.md`. In short: only the release package goes in, the
server runs unprivileged after a root entrypoint drops everything, and the
config departs from the defaults only where Complement's contract forces it,
plus the optional parts of the encryption policy and rate limits. A full run is a pre-release step,
not a per-PR gate (`docs/todos/production-milestone.md`). Every branch run of
`packages.yml` boots the image without Complement (`complement-image`), and
`tests/tooling/test_complement_image.py` tests its scripts directly. A run is
green by `scripts/summarise_complement.py`'s verdict over
`tests/complement/skip-list.toml`, never by `go test`'s exit status (ADR-0234).

## Fuzz testing

Fuzz targets live in `tests/fuzz/` and are built only when `-Dbuild_fuzz=true` is
passed to Meson. They require clang — libFuzzer is a compiler-rt component not
available with GCC.

### Running locally

```bash
sh scripts/run-fuzz-targets.sh --builddir build-fuzz --duration 60
```

Options:
- `--duration <seconds>` — per-target wall-clock budget (default 120)
- `--runs <count>` — libFuzzer `-runs=` cap; useful for quick smoke checks
- `--builddir <path>` — Meson build directory (default `build-fuzz`)

Each target runs under ASan + UBSan with `abort_on_error=1`. The working corpus
accumulates in `build-fuzz/fuzz-corpus/<target>/` across runs.

### Seed corpus

Checked-in seeds live in `tests/fuzz/corpus/<target>/`. The run script copies
them into the working corpus before each run so CI always starts from known-good
inputs. Seeds should be short, valid inputs that exercise distinct parse paths —
the fuzzer extends them automatically through mutation.

### CI schedule

| Trigger | Duration per target |
|---|---|
| Pull request / push | 120 s |
| Weekly (Sunday 02:11 UTC) | 900 s |

The `fuzz` workflow uploads the working corpora and any crash artifacts
(`crash-*`, `leak-*`, `timeout-*`) as a GitHub Actions artifact retained for
14 days.

### Adding a new target

1. Create `tests/fuzz/fuzz_<surface>.cpp` — one `LLVMFuzzerTestOneInput` that
   feeds raw bytes into a single parsing surface. Do not assert specific output;
   assert only that the call does not crash or loop.
2. Register the executable in `tests/fuzz/meson.build` with `fuzz_sanitizer_args`
   for both `cpp_args` and `link_args`. List all transitive static libraries
   explicitly in `link_with` (Meson does not propagate `link_with` from static
   libraries to executables). If the target's library calls into `observability_lib`
   (e.g. `diagnostic_log_summary`), add both `observability_lib` and `platform_lib`
   to `link_with` — `observability_lib` references `platform::HardeningSelfCheck`.
3. Add `run_target <name> "$builddir/tests/fuzz/<name>"` to
   `scripts/run-fuzz-targets.sh`.
4. Add at least two seed files to `tests/fuzz/corpus/<target>/`.
5. Update the target table in `tests/fuzz/CLAUDE.md`.

### Handling a crash finding

When the fuzzer finds a crash:

1. Minimise the input with `<target> -minimize_crash=1 crash-<hash>`.
2. Add the minimised bytes as a regression test in
   `tests/unit/test_<surface>.cpp`:

```cpp
SCENARIO("fuzz regression: <brief description>", "[<surface>][fuzz][regression]") {
    GIVEN("the crashing input") {
        // ...
        WHEN("parsed") {
            // ...
            THEN("it does not crash or produce undefined behaviour") {
                // ...
            }
        }
    }
}
```

3. Add the minimised input to `tests/fuzz/corpus/<target>/` so CI never
   regresses on it.
4. Fix the underlying bug before merging.

## Federation worker outbound IPC tests

`WorkerPool::send_outbound_request`, `FederationProxy::send_outbound_request`, and the
`outbound_http_request` branch in `WorkerEventLoop::run` can only be exercised by spawning
real worker processes over a live IPC channel. These paths belong in
`tests/integration/test_federation_worker_flow.cpp` under the
`MEROVINGIAN_TEST_FEDERATION_WORKER` guard.

The canonical pattern for an outbound IPC scenario is:
1. Construct a `WorkerPool` (or `FederationProxy`) with the real worker binary.
2. Wait for `pool.healthy()` or a `sleep_for(2s)` warm-up.
3. Build an `http::OutboundRequest` with a quick-failing `pinned_addresses` entry
   (e.g. `"host:port:127.0.0.1"` where port 9 is the discard port — ECONNREFUSED in < 1 ms).
4. Call `send_outbound_request()` and `REQUIRE_FALSE(result.ok)`.

For stopped-pool coverage: start a healthy pool, call `pool.stop()` to clear
`workers_`, then call `send_outbound_request()`. The `index >= workers_.size()`
guard fires immediately and returns a non-empty `error_detail` without touching
IPC. Do **not** pass a nonexistent binary path — the constructor calls
`posix_spawn()` directly and throws `std::runtime_error` when the binary is
absent, crashing the GIVEN block before any assertion runs.

### Playing a compromised worker (F-43, ADR-0349)

To test what main does with a worker's reply, without a worker process, set
`runtime.homeserver.test_worker_outbound_route`: it answers every `OutboundAnswerTrust::signature_verified`
call in place of the `FederationProxy`, and an `unverified` call never reaches it. A scenario that expects a
call to stay off the tunnel counts the hook's calls and points the remote server at a closed port, so a forged
body can appear only if main believed the hook (`[f-43]` in
`tests/integration/test_client_outbound_proxy_flow.cpp`). The reply checks themselves
(`validate_worker_outbound_reply`) are pure and tested in `tests/unit/test_federation_proxy.cpp`.

### Test-only environment variables

* `MEROVINGIAN_TEST_DISABLE_HARDENING` — when set to any value,
  `start_runtime()` skips applying seccomp/pledge/unveil sandbox controls.
  The build scripts (`build-linux.sh`, `build-bsd.sh`, `build-wsl.sh`) export
  this variable automatically when they run `meson test`, because the sandbox
  restrictions are permanent in-process and would break the Catch2 runner that
  executes many scenarios in one process. Direct invocations of a test binary
  (for example a focused PostgreSQL integration run) must set it manually.

### The federation worker path (compile-time macro)

`MEROVINGIAN_TEST_FEDERATION_WORKER` is not an environment variable. `tests/meson.build` defines it as a
compile-time macro (`-DMEROVINGIAN_TEST_FEDERATION_WORKER="<path>"`) holding the build-tree path of the built
`merovingian-fed-worker`, for the live federation-worker integration tests. When the macro is not defined,
`tests/integration/test_federation_worker_flow.cpp` defaults it to `""` and those scenarios skip.

### Freezing the event clock

Set `HomeserverRuntime::test_frozen_event_clock_ms` to make every event the
runtime composes carry that `origin_server_ts`, as if the clock stood still or
were stepped back. Use it to reproduce, every time, behaviour that otherwise
needs two requests inside one millisecond, instead of looping a scenario and
hoping for the timing: the `[create-room-collision]` scenarios are the example
(ADR-0156). No production path sets it.

## Live join_room integration tests

`join_room`'s outbound calls always resolve through `federation::discover_server()`,
which unconditionally rejects loopback and private-range addresses
(`src/federation/Security.cpp` `ip_address_is_private_or_loopback`) with no config
or environment override, and production outbound calls never populate an
in-memory CA bundle — so a local test TLS server can never be reached through the
real discovery path, and a test certificate issued by a test CA always fails TLS
verification. `HomeserverRuntime::test_forced_outbound_resolution` (see
`include/merovingian/homeserver/HomeserverRuntime.hpp`) closes that gap: a map from
destination `server_name` to a forced `{resolved_host, resolved_port,
pinned_addresses, trusted_ca_pem}`, consulted first in `perform_sync_outbound_call`
before it would otherwise call `discover_server()`. No production construction
path (`start_runtime`, `main.cpp`, the federation worker) ever populates this
map, so real-server SSRF and TLS-trust behaviour is unchanged.

`tests/integration/test_join_room_flow.cpp` is the canonical example:
1. Issue a test TLS certificate (`write_test_tls_certificate()`, which signs it with a
   throwaway test CA) and stand up a real `TcpAcceptor` +
   `TlsServerContext` (the same pattern as `test_federation_outbound_flow.cpp`)
   answering `make_join` then `send_join`.
2. Set `runtime.test_forced_outbound_resolution[destination]` to route that
   destination at `127.0.0.1:<bound port>` with the test CA's PEM
   (`certificate_pem`) as the trusted CA. Never trust a self-signed server
   certificate as its own anchor: libcurl on Ubuntu 26.10 and later verifies
   through upki, which refuses that (ADR-0650).
3. Call `wire_federation_callbacks(runtime)` **before** setting
   `runtime.federation.remote_key_resolver` — `join_room` calls it internally
   the first time `runtime.federation.pdu_sink` is unset, and that call
   overwrites `remote_key_resolver` with the real DNS/key-fetch resolver,
   clobbering a test double set beforehand. Calling it explicitly first (and
   setting the test resolver *after*) makes `join_room`'s internal call a
   no-op via the `pdu_sink` guard.
4. Drive `join_room` and assert on `runtime.database.persistent_store`/`.rooms`,
   holding `runtime.mutex`. The join's whole state is persisted before it
   returns (ADR-0241), so there is nothing to wait for.

## Expected skips

`meson test` counts a Catch2 test case that called `SKIP()` as passed, so a runner missing a precondition
would pass with the test silently not run. Each CI job that runs Catch2 therefore declares the skips it expects
([ADR-0546](adr/0546-ci-fails-on-a-catch2-skip-its-job-does-not-list.md)):

- `tests/expected_skips.json` holds `groups` (lists of `{test, message?, reason, unverified?}`) and `jobs` (a job
  name mapped to the groups it combines). `test` is the scenario name without the `Scenario: ` prefix;
  `message` is an optional substring the SKIP message must contain; `reason` says why this runner skips it.
- `<name>` is a key of the `jobs` object in `tests/expected_skips.json`. The build scripts take
  `--skip-job <name>` (`build-linux.sh`, `build-bsd.sh`); `build-wsl.sh` has no `--skip-job`, so WSL runs are not
  skip-gated. They set
  `MEROVINGIAN_CATCH_REPORT_DIR`, so every test binary also writes an XML report there, and run
  `scripts/check_expected_skips.py` after the suite. A skip that is not listed for the job fails the job and is
  printed with the test name, message and source line. No report, a truncated report or a bad list also fails.
- A listed skip that did not happen only warns. Remove the entry (or its `unverified` flag) when the runner
  settles.
- Local runs are unchanged: without the variable the binaries use the command line they are given. To check a
  change locally, run a binary with `MEROVINGIAN_CATCH_REPORT_DIR=/some/dir` and then
  `python3 scripts/check_expected_skips.py --job ubuntu --reports /some/dir`.

To add an expected skip: add an entry to the group whose runners skip it (or a new group, then name it under
each job that needs it), with a one-line reason; add `message` when only one reason is acceptable. To add a job,
add it under `jobs` and pass its name to the build script in the workflow. `tests/tooling/test_expected_skips.py`
checks that every entry names an existing test case and that every workflow job passes a known name.
Never list `MEROVINGIAN_TEST_FEDERATION_WORKER is not defined`: on CI that skip means the worker binary was not found.

## Sanitizers and concurrency tests

- CI runs the suite under sanitizers in `.github/workflows/sanitizers.yml`:
  the `asan-ubsan` job (`-Db_sanitize=address,undefined`) catches memory and
  undefined-behaviour defects, and the `tsan` job (`-Db_sanitize=thread`)
  catches data races. ThreadSanitizer is the only sanitizer that detects data
  races; ASan and UBSan are blind to them.
- Any type shared across threads at runtime must have a test that exercises
  `perform`/`run`/dispatch concurrently from multiple threads so TSan can check
  the exercised accesses for data races. A thread-safety claim in a header comment is
  not a substitute for a test that drives the contended path. See the
  concurrency scenario in `tests/unit/test_outbound_client.cpp` for the shape:
  many threads, a release barrier so calls overlap, and an assertion that every
  call returns its own well-formed result.
- TSan suppressions live in `tests/sanitizer/tsan.supp` and may target only
  third-party dependencies. Never suppress a report whose stack runs through
  `merovingian::` code — fix the race instead.

## Coverage

The `coverage` workflow measures line and branch coverage over the whole suite (unit,
conformance, integration with a live PostgreSQL, smoke) and uploads it to Codecov, which
requires a fixed 50% target on a pull request's own lines (patch) and a fixed 60% target on overall line coverage
(project). Each target has a tolerance below it, not a limit on the drop from the base: the patch status passes
down to 45% (5% threshold) and the project status down to 58% (2% threshold), whatever the base was
(`.codecov.yml`; both statuses are non-informational). gcovr runs with
`--exclude-throw-branches` (ADR-0217): the unwinding edge the compiler adds to a call that
may throw is not counted, because only an injected allocation failure reaches it and it
holds no code of ours. The flag works only with GCC's gcov (clang's `llvm-cov gcov` does not
label those edges), so the coverage job alone builds with `gcc-14` and reads its data with
`gcov-14`; every other job builds with clang. Every decision branch still counts, so a partial line means a condition
went one way only. Cover it with a test of the other outcome, not an exclusion marker;
`LCOV_EXCL`/`GCOVR_EXCL` are for code that is genuinely unreachable, with the reason
beside them.

## CI job order

GitHub Actions has no job priority, and the organisation runs at most 20 jobs at once across every pull request; queued
jobs are not served in the order they joined, so the only lever is when a job joins the queue. Jobs join in three tiers
([ADR-0580](adr/0580-the-long-ci-jobs-wait-for-a-gate-so-sonar-and-codeql-take-runners-first.md),
[ADR-0743](adr/0743-analyses-then-build-and-test-then-packages-take-runners.md)): the analyses (`sonarcloud`, CodeQL, `tsan`, `asan-ubsan`, then coverage, fuzzing, clang-tidy,
gitleaks, dependency review and triage) need nothing and join at once; every build and test job in `ci.yml`,
`postgres-integration.yml` and `reproducible-build.yml` that needs no other job `needs:` that workflow's instant gate
`queue-after-analyses`; and every package job in `packages.yml` `needs:` `queue-after-build-and-test`, which sleeps 60
seconds first. Each gated job carries `if: ${{ !cancelled() }}`. CodeRabbit runs on its own service, not on these
runners. The
condition matters: without it a failed gate skips the jobs, and a skipped required check counts as passed.
A job that waits for the gate through another job states its condition on its own needs (`needs.<job>.result`, with
`!cancelled()` or `always()`), never `success()` or `failure()`, written or implicit: both look at every ancestor, the
gate included. `tests/tooling/test_ci_runner_order.py` fails when a job there needs nothing, when the package gate does not wait or a
build and test gate does, when a job behind the gate
has no `if`, uses `success()` or `failure()`, or uses `!cancelled()` without a `needs.<job>.result` check (a job on
`always()` must judge its needs in its steps, which the test cannot read), when an analysis waits for anything, or when the jobs that start at once exceed 20. A new workflow that runs for pull requests adds to that count.

## Catch2 example

```cpp
SCENARIO("SecretBuffer exposes bounded writable storage", "[core][secret]")
{
    GIVEN("a buffer with eight bytes of storage")
    {
        auto buffer = merovingian::core::SecretBuffer{8U};

        WHEN("the first byte is changed")
        {
            buffer.bytes()[0] = 0xAAU;

            THEN("the change is visible and the storage size is unchanged")
            {
                REQUIRE(buffer.bytes()[0] == 0xAAU);
                REQUIRE(buffer.bytes().size() == 8U);
            }
        }
    }
}
```

## Security rationale

Given/When/Then structure improves:

- auditability
- behavioral clarity
- security review readability
- negative-path visibility
- regression analysis
- protocol correctness verification
