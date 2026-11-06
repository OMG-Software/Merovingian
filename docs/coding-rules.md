# Coding rules

Use these rules when writing or reviewing Merovingian code. The C++ rules apply
to production code, tests, and generated C++ scaffolding. Workflow rules also
apply to tools and documentation.

**Must** states a requirement. **Prefer** states the default; explain a departure
in the code or pull request. A passing automated check does not prove that all
requirements are met.

## Authority and related guidance

- Matrix protocol behaviour must conform to the local
  [Matrix specification v1.19](matrix-v1.19-spec/index.md). Other homeservers
  are interoperability references, not the authority.
- Read the root and relevant directory `AGENTS.md` files before making a change.
  If requirements conflict, resolve the conflict before changing the affected code.
- Keep project-wide coding rules in this document. The root `AGENTS.md` must
  require contributors and delegated agents to follow it, rather than copy its
  rules. Directory guidance supplies module-specific requirements. See
  [ADR-0465](adr/0465-root-agent-guidance-requires-the-coding-rules-without-copying-them.md).
- [Security coding rules](security-coding-rules.md) define the security
  constraints and their reasons. This document summarises the common rules;
  it does not replace the module-specific requirements.
- [Testing standards](testing-standards.md) define test design and execution.
  [Platform support](platform-support.md) defines the supported targets.

## Design and interfaces

- Prefer simple code with explicit control flow. A security constraint takes
  priority over convenience or a shorter implementation.
- Put project declarations in `merovingian::<module>`, where the module matches
  the directory. Put helpers used by one `.cpp` file in an anonymous namespace.
- Keep interfaces small. Headers declare interfaces; `.cpp` files contain
  implementations, except where templates, `inline`, or `constexpr` require a
  definition in the header.
- Make each header self-contained. Include the declarations its interface needs.
  Prefer forward declarations when a complete type is not required.
- Use `#pragma once` in headers. Do not put `using namespace` directives in headers.
- Define at most one class or struct per file. Give each class or struct its own
  header and, when needed, a matching source file. Do not combine implementations
  of multiple classes in one source file. Forward declarations do not count as
  definitions. See
  [ADR-0466](adr/0466-define-one-class-or-struct-per-file.md).
- The filename stem must exactly match the class or struct name, including case.
  For example, `RoomState` belongs in `RoomState.hpp` and, when needed,
  `RoomState.cpp`. Do not convert the name to `snake_case`. See
  [ADR-0467](adr/0467-type-filenames-match-the-type-name-exactly.md).
- Put module headers in `include/merovingian/<module>/<name>.hpp` and their
  implementations in `src/<module>/<name>.cpp`. Keep the paths aligned when
  both files exist. Header-only types, executable entry points, and documented
  source-only files such as `src/database/sqlite_store.cpp` do not need an
  artificial counterpart. See the implementation guidance for layout exceptions.
- Use the `m_` prefix for member variables. Mark non-mutating member functions `const`.
- Add a brief function comment that explains its purpose. Document ownership,
  required locks, side effects, and error conditions where they are not clear
  from the interface. Do not repeat the function name as the explanation.

See the [header guidance](../include/merovingian/AGENTS.md) and
[implementation guidance](../src/AGENTS.md) for file and SPDX header conventions.

## Ownership and resource lifetime

- Use RAII for every owned resource, including memory, file descriptors, sockets,
  locks, and thread lifetime. Cleanup must also run on failure paths.
- Do not use raw owning pointers. Prefer values and containers. Use
  `std::unique_ptr` when dynamic ownership is required.
- Use references for required borrowed objects. Use `std::span` or
  `std::string_view` for borrowed sequences. Keep the owner alive and do not
  retain a view, reference, or iterator after an operation that invalidates it.
- Allow unavoidable C API pointers only inside RAII wrappers. Keep allocation,
  deallocation, and ownership transfer inside the wrapper; expose values,
  references, views, or owning handles to callers. This allowance does not
  permit direct `new`, `delete`, `malloc`, `calloc`, `realloc`, or `free` calls
  in project code. See [ADR-0463](adr/0463-confine-unavoidable-c-api-pointers-to-raii-wrappers.md).
- Treat `std::shared_ptr` as a risk that requires explicit verification. Shared
  ownership can hide who controls destruction, retain resources or secrets longer
  than intended, and leak objects through reference cycles. It does not make the
  pointed-to object thread-safe.
- Use shared ownership only when it is required and reviewed. Every declaration
  or creation of shared ownership must have a same-line
  `// SHARED_PTR: reviewed — <reason>` comment. The comment must identify the
  owners, explain why unique ownership is insufficient, and state how lifetime
  and reference-cycle risks were checked. A marker without this rationale is
  insufficient. Do not use shared ownership to avoid deciding who owns a resource.
- Use the existing resource wrappers, such as `core::FileDescriptor` and
  `core::SecretBuffer`. Check the security rules before adding another wrapper.

## Errors and function contracts

- Return expected failures as `std::expected<T, core::Error>`. Invalid input and
  a missing resource are expected failures; do not use exceptions for these paths.
- Reserve exceptions for unexpected failures. Keep RAII cleanup valid when a
  dependency throws. Do not silently convert a failure into a success value.
- Mark returned results `[[nodiscard]]` unless callers may intentionally ignore
  them. This is especially important for errors and resource handles.
- Do not discard an error result merely to silence a warning. When a non-void
  result can safely be ignored, write `std::ignore = expression;`. Do not use `(void)expression` or
  `static_cast<void>(expression)`. See the [warning policy](build-warning-policy.md).
- Mark a function `noexcept` only when it cannot let an exception escape.
  Check its callees and cleanup paths. The annotation does not prove that the
  body cannot throw; an escaping exception terminates the process.
- Destructors must not throw. Mark them `noexcept` explicitly.
- Check numeric ranges before narrowing conversions. A cast does not validate
  a value. Follow the input, size, and error rules in
  [security coding rules](security-coding-rules.md).

## Calls, formatting, and includes

- Use ordinary call syntax for named functions: `function(arguments)`.
- Use `std::invoke` for generic callable dispatch and immediately invoked
  lambdas. Include `<functional>` directly. See
  [ADR-0462](adr/0462-use-std-invoke-for-callable-dispatch-and-immediate-lambdas.md).

  ```cpp
  auto result = std::invoke([&] {
      return compute_result(input);
  });
  ```

- Format C++ with the root `.clang-format`. Let the formatter control spacing,
  line wrapping, and include grouping.
- Use quotes for project includes: `"merovingian/module/name.hpp"`.
  Use angle brackets for standard library and third-party includes.
  Do not add bare relative project includes such as `"name.hpp"`.
- Group includes in this order, with a blank line between groups:
  1. The source file's own matching header.
  2. Other project headers.
  3. Third-party and external headers, including OS headers.
  4. STL and other standard library headers.
  Sort each group alphabetically with case-sensitive ordering. `.clang-format`
  identifies standard library headers by an explicit list of names; a header
  without a directory prefix is not necessarily standard. Keep that list current
  when adopting additional standard headers. See
  [ADR-0512](adr/0512-group-external-headers-before-the-standard-library.md).

## Concurrency and portability

- Do not hold `HomeserverRuntime::mutex` across a blocking network call. Use a
  `homeserver::RuntimeLockRelease` scope from `homeserver/request_lock.hpp`.
  It releases every recursion level held by the caller and restores the lock
  when the scope ends. Do not access protected runtime state while it is released.
- Use RAII lock guards. A manual `.unlock()` or `->unlock()` in production code
  needs a same-line `// LOCK_RELEASE: reviewed — <reason>` comment. Prefer the
  existing release scope. See [ADR-0004](adr/0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md).
- Do not use `std::jthread`, `std::stop_token`, or `std::stop_source` in production
  code or tests. Use `homeserver::PeriodicJob`, `homeserver::StopFlag`, or
  `tests/support/joining_threads.hpp` as appropriate. The supported BSD standard
  libraries do not all provide these facilities. See
  [ADR-0167](adr/0167-no-jthread-or-stop-token-use-std-thread-and-stop-flag.md).
- Use `core::PortableSemaphore`, not `std::counting_semaphore`. Use
  `core::run_bounded_parallel` for work that completes within the call. For work
  that outlives the call, take a `core::SemaphorePermit` immediately after
  acquisition. Do not release a task's slot manually: an exception can skip the
  release and block later work. See
  [ADR-0267](adr/0267-bounded-parallel-work-holds-each-slot-in-an-raii-permit.md).
- Do not assume that releasing a mutex also frees the request thread. Follow
  the outbound concurrency caps and deadlines in
  [HTTP transport](http-transport.md) and the security rules.

## Tests and verification

- Write the behaviour test before changing production code. For a regression,
  confirm that the test fails against the unfixed code.
- Unit tests must use Catch2 `SCENARIO`, `GIVEN`, `WHEN`, and `THEN` macros.
  Put setup in `GIVEN`, the action in `WHEN`, and assertions in `THEN`.
  Prefer one behaviour per scenario. Comment-only phase labels are insufficient.
- Assert precise observable results and state changes. Avoid checks that depend
  only on private implementation details. Include failure and boundary cases,
  especially for security-sensitive code.
- Put protocol requirements in conformance tests where possible. Cite the exact
  Matrix v1.19 section. Do not weaken a conformance assertion to match the code.
- Keep unit tests isolated. Use integration tests for real network and
  cross-module flows. Follow each test directory's `AGENTS.md`.
- Name unit test files `tests/unit/test_<module>.cpp` and integration test files
  `tests/integration/test_<module>_flow.cpp`. Follow the directory guidance when
  splitting a large test file by aspect.
- Register new tests in Meson. Run them directly with a tag filter to confirm
  they execute; Catch2 adds `Scenario: ` to scenario names.
- Run the relevant checks and read their completed results. A process still
  running, a startup abort, or an empty filter is not a pass. A timeout is a failure.
  For a Meson run, read the final `Ok:`, `Fail:`, and `Timeout:` counts from its
  `meson-logs/testlog.txt`.

Use the [testing standards](testing-standards.md) for the BDD example,
concurrency tests, sanitizers, and coverage requirements. Sanitizers can detect
defects on executed paths; a clean run does not prove that all paths are safe.

## Change workflow

- Name SQL migrations `migrations/<NNN>_<description>.sql`, with a zero-padded,
  sequential number. Follow [migration guidance](../migrations/AGENTS.md) before
  adding or changing a migration.
- Update `main` from `origin` before creating a development branch for a feature,
  bug fix, or experiment. Never make development changes on `main`. Follow the
  branch prefix required by the project or tool instructions, and submit changes
  through a pull request.
- Documentation-only changes do not require a version bump. For other changes,
  increment the version once when creating the branch. Update all locations in
  [versioning](versioning.md) together.
- Update `CHANGELOG.md` for every change. Use the
  [documentation update table](AGENTS.md) to find the other required updates.
- Record lasting design decisions and rejected alternatives in the
  [ADR register](adr/index.md). Keep settled rules here or in their owning guide.
- Pin third-party GitHub Actions to a full commit SHA with a trailing release
  comment: `owner/repo@<sha> # vX.Y.Z`. The existing policy exempts `actions/*`,
  `github/*`, and local `./` workflows. See
  [ADR-0266](adr/0266-pin-third-party-github-actions-to-a-full-commit-sha.md).
- Do not bypass a failed check or weaken an assertion to get a passing result.
  Correct the defect or resolve an incorrect requirement with evidence.

## What automated checks cover

| Check | What it checks |
|---|---|
| `scripts/reject-unsafe.sh` | Selected allocation patterns, void-cast discards, required review markers on `std::shared_ptr` and manual lock release, and the libsodium boundary |
| `scripts/check-catch2-bdd-tests.sh` | Required BDD macro patterns in unit test files |
| `scripts/check-unit-test-registration.sh` | Unit test source registration |
| `scripts/rewrite_merovingian_includes.py --check` | Project include quoting |
| `clang-format` with `.clang-format` | C++ formatting and include grouping |
| `tests/tooling/test_packages_workflow.py` | Version consistency and packaging requirements |
| `workflow-action-pinning-tooling` | The GitHub Action pinning policy |

The unsafe-pattern gate scans selected C/C++ extensions under `include/`,
`src/`, and `tests/`; some rules scan only production headers and sources.
It uses text patterns, not a C++ parser. It does not check every allocation form,
raw-pointer declaration, borrowed lifetime, `std::invoke` use, or lock invariant.
For shared ownership, it checks `std::shared_ptr` text and the review marker;
it does not verify the rationale or detect every inferred shared pointer creation.
The BDD gate checks patterns, not whether a test proves the intended behaviour.
Review remains necessary. See [scripts guidance](../scripts/AGENTS.md) for
check entry points and scope.
