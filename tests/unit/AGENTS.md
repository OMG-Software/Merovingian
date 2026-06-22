# tests/unit/ — Unit Tests

Unit tests isolate a single module. They do not touch the network or any module outside the one under test.
SQLite may be used only when testing database-specific module behavior.

## File naming

`test_<module>.cpp` — one file per module, matching `src/<module>/`.
If a module needs many scenarios, split: `test_<module>_<aspect>.cpp`.

## Mandatory structure

Every test uses Catch2 BDD macros. No bare `TEST_CASE` blocks with inline assertions:

```cpp
SCENARIO("descriptive behavior", "[module][tag]")
{
    GIVEN("preconditions")
    {
        // setup: inputs, fixtures, module under test

        WHEN("the action is taken")
        {
            // execute: one call / operation under test

            THEN("the observable result")
            {
                REQUIRE(...);
            }
        }
    }
}
```

Tags: use `[module]` matching the directory (e.g., `[crypto]`, `[auth]`, `[sync]`) plus any cross-cutting tags (`[security]`, `[boundary]`).

## Unit vs. other test directories

| Goes in `unit/` | Does NOT go in `unit/` |
|---|---|
| Single function / class in isolation | Matrix spec MUST/SHOULD → `conformance/` |
| Pure logic, no I/O | Requires database or HTTP → `integration/` |
| Concurrency scenarios for thread-safe types | Live network required → `integration/` (opt-in) |

## Thread safety tests

Any type marked thread-safe at runtime needs a concurrency scenario: many threads,
a release barrier so calls overlap, assert every call returns a valid result.
A comment saying "thread-safe" is not a substitute for a test TSan can exercise.

## Security-sensitive code

Auth, crypto, and token tests require negative-path scenarios:
- Reject invalid inputs (wrong size, wrong prefix, malformed)
- Boundary values (zero-length, max-length, off-by-one)
- Error paths do not leak state or partial output
