# Confine unavoidable C API pointers to RAII wrappers

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The root instructions banned all raw pointers. The security guide banned raw
owning pointers and allowed limited interoperability uses. These statements
gave different answers for C APIs that return pointer handles.

## Considered Options

* Keep a literal ban on all raw pointers and retain the policy conflict.
* Ban raw owning pointers in application interfaces; use references or views for
  borrowing and confine unavoidable C API pointers to RAII wrappers.
* Permit non-owning raw pointers throughout application code.

## Decision Outcome

Chosen option: confine unavoidable C API pointers to RAII wrappers, as selected
by the project owner. Prefer values and containers. Use smart pointers for
dynamic ownership and references or bounded views for borrowing. Wrappers keep
C API ownership transfer and cleanup local and expose safer interfaces.

The wrapper owns its handle; a bare pointer does not transfer ownership between
application components. This policy does not exempt wrappers from the ban on
direct `new`, `delete`, `malloc`, `calloc`, `realloc`, or `free` calls. Use the
library's resource API and a suitable RAII owner.

The rules are recorded in [coding rules](../coding-rules.md#ownership-and-resource-lifetime),
[security coding rules](../security-coding-rules.md#memory-safety-and-resource-ownership),
and the root instructions. This change establishes consistent guidance; it does
not certify or migrate every existing C API use.

### Positive Consequences

* The root and security rules agree.
* Ownership transfer and cleanup can be reviewed in one place.
* Borrowing does not require artificial shared ownership.

### Negative Consequences

* C APIs can require a wrapper before use in application code.
* Text-pattern gates cannot prove pointer ownership or borrowed lifetimes;
  reviewers must still check them.
