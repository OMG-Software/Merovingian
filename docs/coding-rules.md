# Coding rules

This document records project coding rules that apply across production code, tests, tools, and generated scaffolding.

Security-relevant rules — the ones that create a vulnerability if violated, each with a "why" — live in [`security-coding-rules.md`](security-coding-rules.md).

Rules:
- Good security is always more important. Code defensively.
- RAII is non negotiable, use it.
- Prefer references over pointers.
- Discard a result with `std::ignore = expr;`, never a void cast (`static_cast<void>(expr)` or
  `(void)expr`). GCC, unlike clang, does not let a void cast silence `warn_unused_result`, so
  a cast that builds on clang breaks the GCC coverage build under `-Werror`.
  `scripts/reject-unsafe.sh` rejects void casts in C++ files under `include/`, `src/` and `tests/`.
- Top level namespace should be `merovingian`.
- Format C++ code with clang-format using the .clang-format file in the project root.
- Never code against `main` (it's blocked for merge), always use an alternate branch and open a pull request.
- Comment functions with a brief 2 line explanation of why the function is needed.
- Member variables must use `m_` prefix.
- Local project includes use `""`.
- Third-party includes use `<>`.
- Standard library includes use `<>`.
- Include ordering must be (enforced by `.clang-format`, `IncludeBlocks: Regroup`,
  with a source file's matching header placed first):
  1. local project includes
  2. third-party includes under a library directory (`<curl/curl.h>`)
  3. standard library includes
  4. any other angle-bracket header, such as `<sodium.h>`, `<libpq-fe.h>` and
     POSIX headers — `.clang-format` only recognises third-party headers that
     sit under a directory, so these land after the standard library
- Never hold `HomeserverRuntime::mutex` across a blocking network call. That one
  mutex serialises every client-server request and every inbound federation
  transaction, so a call held across it converts one slow peer into a
  whole-process stall. Wrap the network call in a
  `homeserver::RuntimeLockRelease` scope (`homeserver/request_lock.hpp`) and keep
  every read and mutation of runtime state outside it. The scope releases every
  recursion level the calling thread holds, so it is correct whether or not a
  caller further up the stack also holds the mutex.
- Do not use `std::jthread`, `std::stop_token` or `std::stop_source`, in production code or
  tests. The libc++ of FreeBSD and OpenBSD does not provide them, so they break the BSD builds.
  Use `std::thread` and join it from RAII: `homeserver::PeriodicJob` for a background job,
  `homeserver::StopFlag` for a stop request a job polls, and `tests/support/joining_threads.hpp`
  in tests (ADR-0167).
- Never release a semaphore slot by hand. Cap parallel work with `core::run_bounded_parallel`
  (`core/bounded_parallel.hpp`), or, when the tasks must outlive the call, take a
  `core::SemaphorePermit` straight after `acquire()`. A `release()` at the end of a task body is
  skipped when the task throws, and once every slot has leaked that way the next `acquire()`
  waits forever (ADR-0267). Use `core::PortableSemaphore`, not `std::counting_semaphore`, which
  NetBSD's libc++ lacks.
- Use a third-party GitHub Action only pinned to a full commit SHA with its release in a trailing
  comment (`owner/repo@<sha> # vX.Y.Z`). A tag can be moved to other code; `actions/*`,
  `github/*` and local `./` workflows are exempt. `workflow-action-pinning-tooling` enforces it
  (ADR-0266).


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