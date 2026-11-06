# Enums count as types for the one-type-per-file rule

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

[ADR-0466](0466-define-one-class-or-struct-per-file.md) and
[ADR-0467](0467-type-filenames-match-the-type-name-exactly.md) were worded in
terms of classes and structs. When the largest multi-type headers were split,
enums were treated as outside both rules. Some were left beside a class, several
were grouped into shared `*_enums.hpp` headers, and some went into snake_case
headers such as `outbound_error.hpp`. The project owner ruled that this reading
is wrong: an enum is a type and follows the same rules.

## Considered Options

* Apply the rules to classes and structs only, and let enums share a file.
* Apply both rules to enums as well: one enum per file, named exactly after the enum.

## Decision Outcome

Chosen option: both rules apply to enums. An `enum` or `enum class` is a type
for the one-type-per-file rule, and its header's filename stem matches the enum
name exactly. Free functions that only describe the enum, such as its name and
parse functions, may share its header. A type nested inside a class keeps
following [ADR-0513](0513-single-file-helper-types-stay-in-the-anonymous-namespace.md):
it stays with the enclosing type. The same applies to an enum used by only one
`.cpp` file, which stays in that file's anonymous namespace.

Grouping several enums in a shared header was rejected, even though it avoids
include cycles, because it reintroduces the multi-type files the rule exists to
remove. Giving each enum its own header also breaks those cycles.

### Positive Consequences

* A reader finds any type, enum or class, at `<module>/<TypeName>.hpp`.
* Audits can check the rule mechanically without deciding what counts as a type.

### Negative Consequences

* Many small enum headers, each needing its own include.
* Existing headers that pair an enum with a class must be split as they are touched.
