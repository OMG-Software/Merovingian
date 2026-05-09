# Coding rules

This document records project coding rules that apply across production code, tests, tools, and generated scaffolding.

## Tests

All Catch2 unit tests must use Catch2's BDD section macros:

```cpp
SCENARIO("behavior under test", "[area]")
{
    GIVEN("preconditions")
    {
        // setup inputs, fixtures, and preconditions

        WHEN("the behavior runs")
        {
            // execute the behavior under test

            THEN("the expected result is observed")
            {
                // assertions
            }
        }
    }
}
```

Rules:

- Use `SCENARIO` for Catch2 unit tests.
- Use `GIVEN`, `WHEN`, and `THEN` macros from Catch2, not comment-only sections.
- Keep setup inside `GIVEN`.
- Keep the single behavior under test inside `WHEN` where practical.
- Keep assertions inside `THEN`.
- Prefer one behavior per scenario.
- Avoid hidden setup inside assertion expressions when it obscures the Given/When/Then structure.
