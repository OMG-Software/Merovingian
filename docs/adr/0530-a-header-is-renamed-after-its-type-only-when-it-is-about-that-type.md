# A header is renamed after its type only when it is about that type

* Status: accepted, amended by [ADR-0596](0596-every-module-file-is-named-in-pascalcase-including-function-only-headers.md)
* Deciders: James Chapman
* Date: 2026-11-07

Technical Story: the second one-type-per-file split (0.12.80), which covered every header the first split (ADR-0466, ADR-0467) left

## Context and Problem Statement

ADR-0467 names a file after the one type it defines, and lets a header with no type keep a snake_case name. Many headers
sat between the two: one type next to free functions. `redaction.hpp` held `RedactionResult` and `redact_event`.
`edu_idempotence.hpp` held `EduIdempotenceWindow` and two message-ID functions. Renaming every such header after its type
would name `redaction.hpp` after a result struct. Leaving the type in place breaks ADR-0467. Which applies, and what
decides it?

## Considered Options

* Rename the header after its type when the header is about that type. Otherwise extract the type and keep the
  snake_case header for the functions
* Always rename the header after its one type
* Always extract the type, so every header with functions is snake_case

## Decision Outcome

Chosen option: "rename when the header is about the type, otherwise extract".

* **Rename** when the header is named after the type's concept and its functions work on that type.
  `edu_idempotence.hpp` became `EduIdempotenceWindow.hpp`, and `request_lock.hpp` became `RequestLockScope.hpp`. The
  type is the header's reason to exist, and its functions are the type's own operations.
* **Extract** when the type only carries a function's input or result. `RedactionResult` moved to `RedactionResult.hpp`,
  and `redaction.hpp` keeps `redact_event`. A header named after a result struct would hide the function people look for.
* A multi-type header follows the same test for its one candidate primary type. A type that is not primary moves out.
  When keeping a primary type would make two headers include each other, the primary moves out too, and the header keeps
  only functions. This happened with `outbound_transaction.hpp`, `file_metadata.hpp` and `registration.hpp`.
* An extracted type takes its out-of-line members to `<TypeName>.cpp`. When those members share several
  anonymous-namespace helpers with the rest of the old `.cpp`, they stay where they are until ADR-0513's module-internal
  header for those helpers is worth having. That applies now to `PostgresqlConnection` (about eight helpers shared in
  `postgresql_store.cpp`) and the `LandlockHardeningOps` constructor (five Linux-only syscall wrappers in
  `landlock_hardening.cpp`). The type's header is still its own.

Rule for future code: a new header with one type and functions is named after the type only if a reader looking for
the functions would look for the type's name. Otherwise the type gets its own file.

### Positive Consequences

* Every header now follows ADR-0466 and ADR-0467. A file named after a type holds that type, and a snake_case header
  holds only functions, constants and aliases.
* A function is still found in the header named for what it does.

### Negative Consequences

* The test is a judgement, not a mechanical rule. Two reviewers can disagree on a borderline header such as
  `listener.hpp`, which kept `RuntimeListeners` and became `RuntimeListeners.hpp`.
* Two types keep their member definitions in a `.cpp` named for something else, as listed above.

## Pros and Cons of the Options

### Always rename the header after its one type

* Good, because it is mechanical.
* Bad, because `redaction.hpp`, `event_query.hpp` and `key_signatures.hpp` would be named after a result or helper
  struct, and their functions would be hard to find.

### Always extract the type

* Good, because it is mechanical too.
* Bad, because a class with its own operations, such as `EduIdempotenceWindow` or `IpcChannel`, would be split from
  them, leaving a snake_case header that only forwards to it.

## Links

* Refines [ADR-0467](0467-type-filenames-match-the-type-name-exactly.md)
* Applies [ADR-0513](0513-single-file-helper-types-stay-in-the-anonymous-namespace.md)
