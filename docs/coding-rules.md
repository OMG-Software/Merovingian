# Coding rules

This document records project coding rules that apply across production code, tests, tools, and generated scaffolding.

Rules:
- Good security is always more important. Code defensively.
- RAII is non negotiable, use it.
- Prefer references over pointers.
- Top level namespace should be `merovingian`.
- Format C++ code with clang-format using the .clang-format file in the project root.
- Never code against `main` (it's blocked for merge), always use an alternate branch and open a pull request.
- Comment functions with a brief 2 line explanation of why the function is needed.


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
- Tests should test behaviour and state rather than specific outcomes.