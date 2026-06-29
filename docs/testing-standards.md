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
