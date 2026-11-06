# Define one class or struct per file

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The coding guide required one primary type per header. That wording allowed
additional class definitions and did not prevent one source file from combining
several classes' implementations. The project owner requested one class per file.

## Considered Options

* Keep one primary type per header and allow additional classes in the same file.
* Require a separate header and, when needed, source file for each class or struct.

## Decision Outcome

Chosen option: a separate file pair for each class or struct. Define at most one
class or struct in a file and do not combine implementations of multiple classes
in a source file. Forward declarations do not count as definitions. Use filenames
that match the type, as specified in [coding rules](../coding-rules.md#design-and-interfaces).

This documentation change establishes the rule. It does not audit or refactor
existing type definitions.

### Positive Consequences

* A type's filename identifies its declaration and implementation.
* A file does not accumulate additional classes under the label of helper types.

### Negative Consequences

* Small helper classes and structs also require separate files.
* Authors must maintain additional headers and source registrations when needed.
