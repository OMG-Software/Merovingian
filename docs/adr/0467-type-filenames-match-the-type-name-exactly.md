# Type filenames match the type name exactly

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The coding guide combined matching type filenames with a `snake_case`
conversion. The project owner clarified that the filename must match the class
name itself, including its case.

## Considered Options

* Convert class and struct names to `snake_case` for their filenames.
* Match class and struct names exactly in their filename stems.

## Decision Outcome

Chosen option: match the type name exactly. A class or struct named `RoomState`
uses `RoomState.hpp` and, when an implementation file is needed, `RoomState.cpp`.
The extension is not part of the type name. Do not change the spelling or case.

This clarifies the filename requirement associated with
[ADR-0466](0466-define-one-class-or-struct-per-file.md). Its one-class-or-struct-per-file
rule remains in effect. The maintained rule is in
[coding rules](../coding-rules.md#design-and-interfaces).

This documentation change does not rename existing source files.

### Positive Consequences

* Authors can locate a type's files without applying a naming conversion.
* The filename and type name have one spelling and case.

### Negative Consequences

* Existing filenames may differ until they are migrated in a separate change.
* Case-only renames require care on case-insensitive filesystems.
