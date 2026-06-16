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
   (e.g. `diagnostic_log_summary`), add it to `link_with` too.
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
