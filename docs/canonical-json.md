# Canonical JSON

This capability note describes the Matrix signing-critical canonical JSON
foundation.

## Current scope

Implemented now:

- project-owned canonical JSON value model
- `yyjson`-backed strict JSON parser behind the project-owned canonical JSON
  boundary
- bounded conversion into the project-owned value model
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

- room/event fixture suite beyond canonical JSON shape fixtures
- full Matrix room-version fixture suite

## Rules

Canonical JSON is security-critical because Matrix event IDs and signatures
depend on deterministic serialization. The event engine now uses canonical JSON
for Matrix content hashes, reference-hash event IDs, and redacted Ed25519
signing payloads.

The parser and serializer must:

- never emit insignificant whitespace
- sort object keys lexicographically
- reject duplicate object keys
- reject invalid UTF-8
- reject lossy numeric forms
- preserve integer values without lossy conversion
- avoid dependency-defined signing semantics

`yyjson` is used only to parse strict RFC 8259 JSON and validate UTF-8. A small
C adapter owns the direct `yyjson.h` include so C++ static analysis and warning
policy stay focused on project code. The parser copies parsed data into
`merovingian::canonicaljson::Value` and applies Matrix-specific policy there.
No `yyjson_*` type is exposed outside the canonical JSON implementation.

## Numeric policy

Only signed 64-bit integers are accepted in the current implementation.
Floating-point values, exponent notation, and unsigned values outside the
signed 64-bit range are rejected even though `yyjson` can parse broader JSON
number forms. This keeps Matrix signing inputs lossless and deterministic.

## Signable object view

`make_signable_object_view` currently serializes the supplied canonical JSON
value deterministically. Later event-signing work will layer Matrix-specific
event field elision and signing-key metadata over this primitive.
