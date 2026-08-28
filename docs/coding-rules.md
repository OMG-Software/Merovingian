# Coding rules

This document records project coding rules that apply across production code, tests, tools, and generated scaffolding.

Security-relevant rules — the ones that create a vulnerability if violated, each with a "why" — live in [`security-coding-rules.md`](security-coding-rules.md).

Rules:
- Good security is always more important. Code defensively.
- RAII is non negotiable, use it.
- Prefer references over pointers.
- Top level namespace should be `merovingian`.
- Format C++ code with clang-format using the .clang-format file in the project root.
- Never code against `main` (it's blocked for merge), always use an alternate branch and open a pull request.
- Comment functions with a brief 2 line explanation of why the function is needed.
- Member variables must use `m_` prefix.
- Local project includes use `""`.
- Third-party includes use `<>`.
- Standard library includes use `<>`.
- Include ordering must be:
  1. local project includes
  2. third-party includes
  3. standard library includes
- Never hold `HomeserverRuntime::mutex` across a blocking network call. That one
  mutex serialises every client-server request and every inbound federation
  transaction, so a call held across it converts one slow peer into a
  whole-process stall. Wrap the network call in a
  `homeserver::NetworkIoUnlock` scope (`homeserver/request_lock.hpp`) and keep
  every read and mutation of runtime state outside it.


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