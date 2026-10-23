# Branch coverage excludes the compiler's exception edges

* Status: accepted
* Date: 2026-10-23

Technical Story: `codecov/patch` on PR #527 (0.12.42)

## Context and Problem Statement

The coverage job runs gcovr over clang's gcov data. When a call may throw while
objects that need destroying are alive, clang emits a second edge out of the call to an
unwinding block that runs those destructors and rethrows. gcov reports that edge as a
branch. In this codebase almost every call can throw only `std::bad_alloc` (building a
`std::string`, growing a vector): the SQLite and libpq calls underneath are C, and the
project reports errors as values, not exceptions (`src/AGENTS.md`). A line such as
`return {false, "unable to open SQLite persistent store", {}};` therefore shows as
"partial" even when a test runs it, and Codecov counts a partial line as a miss.

On PR #527 this held patch coverage at 34% against a 45% pass mark after every reachable
error path had a test: the remaining partials were nearly all exception edges. How should
branch coverage treat them?

## Decision Drivers

* Branch coverage should show untested decisions in our code, not the C++ exception model.
* No edge of this kind contains code of ours: it runs compiler-generated destructors.
* Many functions here are `noexcept`, so an allocation failure inside them terminates
  rather than unwinds, whatever a test does.
* The project bans `new`/`delete` and prefers simple solutions.

## Considered Options

* Exclude exception edges (`gcovr --exclude-throw-branches`), building the coverage job
  with GCC 14
* The same flag with the coverage job left on clang
* Count partially covered lines as covered in Codecov (`parsers.cobertura.partials_as_hits`)
* Inject allocation failures in tests (a replacement global allocator failing the Nth call)
* Keep counting them and leave `codecov/patch` red where they dominate
* Mark the affected lines excluded (`GCOVR_EXCL_LINE`) one by one

## Decision Outcome

Chosen option: "Exclude exception edges, building the coverage job with GCC 14", because it
removes only branches the compiler added and keeps every branch the code itself takes
(`if`, `&&`, `||`, `?:`, loops) in the count. Line coverage is unaffected. Owner decision,
2026-10-23.

**The flag needs GCC.** gcovr can only exclude an exception edge that gcov labels as one.
GCC's gcov does; clang's `llvm-cov gcov` does not. Tested with gcovr 7.0 on a probe whose
error path builds a `std::string`: under clang 18 the probe has 10 branches with or without
the flag; under GCC 13 the flag takes it from 20 to 17, leaving the decision branches. The
first attempt, on clang, therefore changed nothing, and patch coverage on PR #527 stayed at
34%. The coverage job alone builds with `gcc-14`/`g++-14` and reads its data with
`gcov-14`; every other job stays on clang. GCC ≥ 14 is already a supported compiler
(`docs/platform-support.md`). `tests/tooling/test_coverage_workflow.py` pins the flag, the
compiler and the gcov executable together, so none of them can change alone.

A test may still need to show behaviour under an exception the code throws on purpose;
that is ordinary test design, not a reason to count the unwinding edges.

### Positive Consequences

* A partial line in the report means a decision went untested.
* Branch figures rise project-wide for the same tests; the jump in the first report after
  this change is the measurement changing, not new tests.

### Negative Consequences

* A path that only an allocation failure reaches is no longer visible in branch coverage.
  None of those paths contains code of ours.
* Coverage is measured on a different compiler from every other job. It is the only CI job
  that builds with GCC, so a GCC-only warning under `-Werror` surfaces there first.

## Pros and Cons of the Options

### The same flag with the coverage job left on clang

* Good, because every job would use one compiler.
* Bad, because it does nothing: `llvm-cov gcov` does not label exception edges.

### Count partially covered lines as covered in Codecov

* Good, because it is one line of `.codecov.yml` and works with clang.
* Bad, because a line whose real condition only ever went one way would count as covered
  too, which is exactly what branch coverage exists to show.

### Inject allocation failures in tests

* Good, because the edges would really run.
* Bad, because the test checks compiler-generated cleanup, not our logic; which allocation
  is "the Nth" changes with any reordering or standard-library update; and `noexcept`
  functions terminate instead of unwinding.

### Keep counting them

* Good, because nothing changes.
* Bad, because `codecov/patch` fails on correct, fully exercised code, and teaches
  everyone to ignore it.

### Mark lines excluded one by one

* Good, because it is local.
* Bad, because it hides whole lines, decision branches included. The repository reserves
  `LCOV_EXCL`/`GCOVR_EXCL` markers for code that is genuinely unreachable.

## Links

* [.github/workflows/coverage.yml](../../.github/workflows/coverage.yml) — the gcovr call
* [docs/testing-standards.md](../testing-standards.md) — "Coverage"
