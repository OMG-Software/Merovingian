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
