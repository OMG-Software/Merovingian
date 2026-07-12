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
- JS-safe-integer range enforcement (`[-(2^53)+1, (2^53)-1]`) for the strict
  signing parser
- rejection of floating-point/exponent numbers in the strict signing parser
- a second general-purpose parser (`parse_json()`, alongside the strict
  `parse_lossless()`) that preserves doubles and exponent notation for
  non-signing payloads such as account data and `m.tag` room tags
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

The strict signing parser (`parse_lossless()`) only accepts integers within
the JS-safe-integer range `[-(2^53)+1, (2^53)-1]`. Floating-point values,
exponent notation, and integers outside that range are rejected even though
`yyjson` can parse broader JSON number forms. This keeps Matrix signing
inputs lossless and deterministic. The separate general-purpose parser
(`parse_json()`) accepts doubles and exponent notation for payloads that are
never signed.

## Signable object view

`make_signable_object_view` currently serializes the supplied canonical JSON
value deterministically. Later event-signing work will layer Matrix-specific
event field elision and signing-key metadata over this primitive.
