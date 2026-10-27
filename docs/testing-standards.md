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

## Socket calls in integration tests

Every socket call in an integration test has a deadline, so a server that never
answers fails one scenario instead of holding the whole binary until meson's
timeout kills it. Connect with `merovingian::tests::connect_within`
(`tests/integration/bounded_connect.hpp`), never a blocking `::connect()`: on
OpenBSD 7.9 a blocking connect to the test's own in-process listener never
returned. Bound reads and writes with `poll` or `SO_RCVTIMEO`/`SO_SNDTIMEO`.

## Live PostgreSQL scenarios that need a quiet store

The live PostgreSQL scenarios share one database (`MEROVINGIAN_TEST_POSTGRESQL_URI`),
and a runtime started on it replays the durable queues earlier scenarios left there
(the dispatch worker's `federation_transactions`, the retry job's `deferred_pdus`). Those
background workers then write to the store whenever a retry falls due. A scenario that asserts
on every write the store commits (`enable_statement_capture` and an empty
`captured_statements`), or that needs an empty schema, runs on a database of its own:
`merovingian::tests::ScratchPostgresqlDatabase`
(`tests/integration/scratch_postgresql_database.hpp`), declared before anything that
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

### Test-only environment variables

* `MEROVINGIAN_TEST_FEDERATION_WORKER` — absolute path to the
  `merovingian-fed-worker` binary. Required by the live federation-worker
  integration tests; when unset those scenarios are skipped.
* `MEROVINGIAN_TEST_DISABLE_HARDENING` — when set to any value,
  `start_runtime()` skips applying seccomp/pledge/unveil sandbox controls.
  The build scripts (`build-linux.sh`, `build-bsd.sh`, `build-wsl.sh`) export
  this variable automatically when they run `meson test`, because the sandbox
  restrictions are permanent in-process and would break the Catch2 runner that
  executes many scenarios in one process. Direct invocations of a test binary
  (for example a focused PostgreSQL integration run) must set it manually.

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
(`src/federation/security.cpp` `ip_address_is_private_or_loopback`) with no config
or environment override, and production outbound calls never populate an
in-memory CA bundle — so a local test TLS server can never be reached through the
real discovery path, and a self-signed test certificate always fails TLS
verification. `HomeserverRuntime::test_forced_outbound_resolution` (see
`include/merovingian/homeserver/runtime.hpp`) closes that gap: a map from
destination `server_name` to a forced `{resolved_host, resolved_port,
pinned_addresses, trusted_ca_pem}`, consulted first in `perform_sync_outbound_call`
before it would otherwise call `discover_server()`. No production construction
path (`start_runtime`, `main.cpp`, the federation worker) ever populates this
map, so real-server SSRF and TLS-trust behaviour is unchanged.

`tests/integration/test_join_room_flow.cpp` is the canonical example:
1. Generate a self-signed TLS certificate and stand up a real `TcpAcceptor` +
   `TlsServerContext` (the same pattern as `test_federation_outbound_flow.cpp`)
   answering `make_join` then `send_join`.
2. Set `runtime.test_forced_outbound_resolution[destination]` to route that
   destination at `127.0.0.1:<bound port>` with the certificate's PEM as the
   trusted CA.
3. Call `wire_federation_callbacks(runtime)` **before** setting
   `runtime.federation.remote_key_resolver` — `join_room` calls it internally
   the first time `runtime.federation.pdu_sink` is unset, and that call
   overwrites `remote_key_resolver` with the real DNS/key-fetch resolver,
   clobbering a test double set beforehand. Calling it explicitly first (and
   setting the test resolver *after*) makes `join_room`'s internal call a
   no-op via the `pdu_sink` guard.
4. Drive `join_room` and assert on `runtime.database.persistent_store`/`.rooms`.
   To wait for the background membership-fill task (see `docs/threat-model.md`
   "Fast join / partial-state trade-off") deterministically rather than
   sleeping, lock `runtime.orphan_futures_mutex_` and call `.wait()` on every
   valid future in `runtime.orphan_futures_` — waiting does not consume or
   invalidate a `std::future`, so this is safe to do from the test thread
   before making further assertions.

## Sanitizers and concurrency tests

- CI runs the suite under sanitizers in `.github/workflows/sanitizers.yml`:
  the `asan-ubsan` job (`-Db_sanitize=address,undefined`) catches memory and
  undefined-behaviour defects, and the `tsan` job (`-Db_sanitize=thread`)
  catches data races. ThreadSanitizer is the only sanitizer that detects data
  races; ASan and UBSan are blind to them.
- Any type shared across threads at runtime must have a test that exercises
  `perform`/`run`/dispatch concurrently from multiple threads so TSan can prove
  the access pattern is race-free. A thread-safety claim in a header comment is
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
requires 50% on a pull request's own lines (`.codecov.yml`). gcovr runs with
`--exclude-throw-branches` (ADR-0217): the unwinding edge the compiler adds to a call that
may throw is not counted, because only an injected allocation failure reaches it and it
holds no code of ours. The flag works only with GCC's gcov (clang's `llvm-cov gcov` does not
label those edges), so the coverage job alone builds with `gcc-14` and reads its data with
`gcov-14`; every other job builds with clang. Every decision branch still counts, so a partial line means a condition
went one way only. Cover it with a test of the other outcome, not an exclusion marker;
`LCOV_EXCL`/`GCOVR_EXCL` are for code that is genuinely unreachable, with the reason
beside them.

## Catch2 example

```cpp
TEST_CASE("SecretBuffer exposes bounded writable storage", "[core][secret]") {
    // Given
    auto buffer = merovingian::core::SecretBuffer{8U};

    // When
    buffer.bytes()[0] = 0xAAU;

    // Then
    REQUIRE(buffer.bytes()[0] == 0xAAU);
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
