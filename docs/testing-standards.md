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
