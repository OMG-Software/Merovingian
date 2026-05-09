# Canonical JSON

Milestone 4 starts the Matrix signing-critical canonical JSON layer.

## Current scope

Implemented now:

- project-owned canonical JSON value model
- deterministic canonical serialization
- whitespace-free arrays and objects
- lexicographic object key ordering
- duplicate object-key rejection
- string escaping for JSON control escapes
- stable serializer error names
- serializer unit tests
- serializer fuzz target

Not implemented yet:

- full JSON parser
- UTF-8 normalization/validation beyond control-character rejection
- Matrix fixture differential tests
- signable object view
- event-signing integration
- JSON dependency wrapper

## Rules

Canonical JSON is security-critical because Matrix event IDs and signatures depend on deterministic serialization.

The serializer must:

- never emit insignificant whitespace
- sort object keys lexicographically
- reject duplicate object keys
- reject strings that cannot be represented safely
- preserve integer values without lossy conversion
- avoid dependency-defined signing semantics

The parser and Matrix fixture suite are later milestone 4 follow-up work.
