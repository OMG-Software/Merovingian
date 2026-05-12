# Canonical JSON

This capability note describes the Matrix signing-critical canonical JSON
foundation.

## Current scope

Implemented now:

- project-owned canonical JSON value model
- bounded lossless JSON parser
- deterministic canonical serialization
- whitespace-free arrays and objects
- lexicographic object key ordering
- duplicate object-key rejection during parsing and serialization
- UTF-8 validation for parsed strings
- Unicode escape decoding, including surrogate pairs
- signed 64-bit integer range enforcement
- rejection of floating-point/exponent numbers
- stable parser and serializer error names
- signable object view scaffolding
- Matrix-style fixture tests
- parser and serializer unit tests
- parser/serializer fuzz target

Not implemented yet:

- event-signing integration
- room/event fixture suite beyond canonical JSON shape fixtures
- JSON dependency wrapper
- full Matrix event ID/signature pipeline

## Rules

Canonical JSON is security-critical because Matrix event IDs and signatures depend on deterministic serialization.

The parser and serializer must:

- never emit insignificant whitespace
- sort object keys lexicographically
- reject duplicate object keys
- reject invalid UTF-8
- reject lossy numeric forms
- preserve integer values without lossy conversion
- avoid dependency-defined signing semantics

## Numeric policy

Only signed 64-bit integers are accepted in the current implementation.
Floating-point values and exponent notation are rejected until Matrix-specific
numeric handling is reviewed with signing fixtures.

## Signable object view

`make_signable_object_view` currently serializes the supplied canonical JSON
value deterministically. Later event-signing work will layer Matrix-specific
event field elision and signing-key metadata over this primitive.
