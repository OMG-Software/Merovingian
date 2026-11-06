# Single-file helper types stay in the anonymous namespace

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

[ADR-0466](0466-define-one-class-or-struct-per-file.md) requires at most one
class or struct per file. The coding rules also require helpers used by one
`.cpp` file to live in that file's anonymous namespace. Large source files such
as `src/homeserver/client_server.cpp` define dozens of private request-body and
path-part structs. The two rules conflict for those helpers, and they do not say
whether a type nested inside a class counts as a second type.

## Considered Options

* Move every helper struct, including single-file helpers, to its own header.
* Keep single-file helpers in the anonymous namespace; give a helper its own
  file only when more than one file needs it.
* Extract nested types to their own files as well.

## Decision Outcome

Chosen option: keep single-file helpers in the anonymous namespace, and keep
nested types with their enclosing type. A helper class or struct used by only one
`.cpp` file stays in that file's anonymous namespace and does not count against
the one-type-per-file rule. When a second file needs the helper, move it to its
own file, named after the type
([ADR-0467](0467-type-filenames-match-the-type-name-exactly.md)), instead of
copying it. Helper code must not be duplicated across files. A type nested
inside a class or struct is part of that type and stays in its file.

Moving every helper to its own header was rejected: it would publish
implementation details in `include/` and give them external linkage, which the
anonymous-namespace rule exists to prevent. Extracting nested types was rejected
because it changes APIs such as `Foo::Options` without separating any
responsibility.

### Positive Consequences

* Private helpers keep internal linkage and stay next to their only user.
* Splitting a large source file cannot leave two copies of a helper behind.

### Negative Consequences

* A large source file may still define many helper types; its size must be
  managed by splitting responsibilities, not by moving helpers out one by one.
