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
- Define at most one class, struct, or enum per file. An `enum` and an
  `enum class` count as types for this rule. Give each type its own header and,
  when needed, a matching source file. Do not combine implementations of
  multiple classes in one source file. Forward declarations do not count as
  definitions. See
  [ADR-0466](adr/0466-define-one-class-or-struct-per-file.md) and
  [ADR-0514](adr/0514-enums-count-as-types-for-the-one-type-per-file-rule.md).
- A type nested inside a class or struct is part of its enclosing type and stays
  in the enclosing type's file. Do not extract it only to satisfy the
  one-type-per-file rule.
- A helper class or struct used by only one `.cpp` file stays in that file's
  anonymous namespace; it does not count against the one-type-per-file rule.
  When a second file needs the helper, move it to its own file, named after the
  type, rather than copying it. Do not duplicate a helper type or function across
  files. See
  [ADR-0513](adr/0513-single-file-helper-types-stay-in-the-anonymous-namespace.md).
- The filename stem must exactly match the class, struct, or enum name,
  including case. For example, `RoomState` belongs in `RoomState.hpp` and, when
  needed, `RoomState.cpp`; `enum class OutboundError` belongs in
  `OutboundError.hpp`. Do not convert the name to `snake_case`. A header or
  source that defines no type, only free functions and constants, is named in
  PascalCase after its concept (`PolicyEngine.hpp`, `SqliteStore.cpp`); when
  that name is already a type's file in the directory, add `Support`
  (`FileMetadataSupport.hpp`). Executable entry points, `test_*.cpp` and
  `fuzz_*.cpp` keep their lower-case names. See
  [ADR-0467](adr/0467-type-filenames-match-the-type-name-exactly.md) and
  [ADR-0596](adr/0596-every-module-file-is-named-in-pascalcase-including-function-only-headers.md).
- Put module headers in `include/merovingian/<module>/<name>.hpp` and their
  implementations in `src/<module>/<name>.cpp`. Keep the paths aligned when
  both files exist. Header-only types, executable entry points, and documented
  source-only files such as `src/database/SqliteStore.cpp` do not need an
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
  `static_cast<void>(expression)`. `scripts/reject-unsafe.sh` rejects both forms
  (GCC, unlike clang, does not let a void cast silence `warn_unused_result`); see the
  [warning policy](build-warning-policy.md).
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

- Format C++ with the root `.clang-format`, by running `scripts/format_code.py`
  on a project directory (`scripts/format_code.py src`; `--dry-run` lists the
  files first). The script walks its directory recursively with no exclusions,
  so run from the repository root with no argument it also rewrites `.worktrees/`,
  `build*/` and `subprojects/`. Never run it unscoped.
  Formatting is manual: no hook or CI job runs the formatter. Let the formatter
  control spacing, line wrapping, and include grouping.
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
  `homeserver::RuntimeLockRelease` scope from `homeserver/RuntimeLockRelease.hpp`.
  It releases every recursion level held by the caller and restores the lock
  when the scope ends. Do not access protected runtime state while it is released.
- Lock `HomeserverRuntime::mutex` through `homeserver::RuntimeLock` (a
  `std::unique_lock<RuntimeMutex const>`). The mutex is not `mutable` and its
  lock functions are `const`. See
  [ADR-0522](adr/0522-the-runtime-mutex-locks-through-const.md). It implements
  its recursion over a plain `std::mutex`; do not swap in `std::recursive_mutex`.
  See [ADR-0524](adr/0524-the-runtime-mutex-implements-its-recursion-over-std-mutex.md).
- A `const` member function changes only members that are synchronised (a mutex
  or an atomic) or that it guards with the object's own mutex. A type that is not
  thread-safe fills its caches through non-`const` functions, never `mutable`
  members. See
  [ADR-0525](adr/0525-a-cache-that-is-not-thread-safe-is-not-hidden-behind-const.md).
- Use RAII lock guards. A manual `.unlock()` or `->unlock()` in production code
  needs a same-line `// LOCK_RELEASE: reviewed — <reason>` comment. Prefer the
  existing release scope. See [ADR-0004](adr/0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md).
- Do not use `std::jthread`, `std::stop_token`, or `std::stop_source` in production
  code or tests. Use `homeserver::PeriodicJob`, `homeserver::StopFlag`, or
  `tests/support/JoiningThreads.hpp` as appropriate. The supported BSD standard
  libraries do not all provide these facilities. See
  [ADR-0167](adr/0167-no-jthread-or-stop-token-use-std-thread-and-stop-flag.md).
- Use `core::PortableSemaphore`, not `std::counting_semaphore`. Use
  `core::run_bounded_parallel` for work that completes within the call. For work
  that outlives the call, take a `core::SemaphorePermit` immediately after
  acquisition. Do not release a task's slot manually: an exception can skip the
  release and block later work. See
  [ADR-0267](adr/0267-bounded-parallel-work-holds-each-slot-in-an-raii-permit.md).
- A copyable or movable type that guards members holds `core::CopyableMutex` (and
  `core::CopyableConditionVariable`) by value. Never keep a mutex behind a
  `std::unique_ptr` or `std::shared_ptr`. Take the lock with `acquire()`. See
  [ADR-0517](adr/0517-guarded-value-types-hold-their-mutex-by-value.md).
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
| `scripts/check-unit-test-isolation.sh` | No file under `tests/unit/` names a function that builds a runtime or drives the client-server stack (ADR-0593); meson test `unit-test-isolation`, covered by `unit-test-isolation-tooling` |
| `scripts/rewrite_merovingian_includes.py --check` | Project include quoting |
| `include-order-tooling` (`tests/tooling/test_include_order.py`) | Include grouping and ordering. Nothing else checks formatting, and no tool enforces `.clang-format` |
| `scripts/check-conformance-gate.sh` | Runs `meson test conformance-tests` in a given build directory (CI, per build). It does not detect a removed conformance test |
| `scripts/check_expected_skips.py` | Fails a CI job when a Catch2 test case skipped that the job's `jobs` entry in `tests/expected_skips.json` does not list; unusable reports fail closed (ADR-0546; covered by `expected-skips-tooling`) |
| `scripts/check-elf-hardening.sh` | Reads a built ELF binary's headers with `readelf` and fails if PIE, RELRO, `BIND_NOW` or a non-executable stack is missing |
| `scripts/check-startup-hardening-gate.sh` | Boots a packaged `merovingian-server` and fails unless every startup hardening self-check reports `enabled` and the server stops cleanly on SIGTERM |
| `scripts/check-release-readiness.sh` | Required release, packaging and dependency files exist; legacy hash strings and project-local hashing are absent from the sources; the release workflow produces attestations, checksums and GPG signatures; wraps are pinned; the licence summary generates; both publishing workflows generate the SBOM and it generates (ADR-0598) |
| `scripts/check-staged-changelog-docs.sh` | Pre-commit: a staged change under code, tests, packaging, scripts or build files also stages `CHANGELOG.md` and a `docs/*.md` file (`MEROVINGIAN_SKIP_CHANGE_DOC_CHECK=1` skips it) |
| `scripts/verify-wrap-pins.sh` | Every `subprojects/*.wrap` is an immutable `[wrap-file]` with a 64-character lowercase hex `source_hash`; `[wrap-git]` is refused |
| `ci-run-scope-tooling`, `ci-runner-order-tooling` | Each workflow runs once per pull request head and the PostgreSQL job runs only what uses PostgreSQL (ADR-0511); Sonar and CodeQL start before queued jobs behind the gate (ADR-0580) |
| `workflow-pip-locking-tooling` | Every workflow `pip install` uses hash-locked wheels from a requirements file (ADR-0313) |
| `security-workflow-tooling` | The security workflows (secret scan, dependency review and triage, sanitizers, CodeQL) and their configuration files keep the settings the release gate relies on, and both publishing workflows attach the SBOM before signing |
| `generate-sbom-tooling` | `scripts/generate_sbom.py` names every shipped licence row with its licence and wrap pin, is deterministic, and refuses an unmapped row, wrap or section (ADR-0598) |
| `release-workflow-tooling`, `stage-release-tarball-tooling` | A release tag must name the `meson.build` version, 0.x releases are prereleases, and release tarballs carry every executable `meson install` installs, both workers included (ADR-0597) |
| `docs-site-tooling` | The documentation site builds strictly on every branch, only `main` deploys it, its dependencies are hash-locked, and every published document has a `mkdocs.yml` nav entry |
| `catch-report-capture-tooling` | A test binary writing its CI skip report still lets a test capture `std::cout` (ADR-0546) |
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
