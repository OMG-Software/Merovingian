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
  `parse_lossless()`) that preserves doubles and exponent notation; this is
  the project's general-purpose non-signing JSON parser, used throughout the
  codebase (appservice registration/client payloads, federation IPC frames,
  the worker pool, federation request routing, push gateway payloads, sliding
  sync, trust & safety) and not limited to account data and `m.tag`
- DoS bounds enforced during parsing: maximum nesting depth of 64
  (`max_depth`, `src/canonicaljson/parser.cpp`) and a maximum of 65536 members
  per object (`max_object_members`, `include/merovingian/canonicaljson/parser.hpp`),
  with `O(n)` duplicate-key detection (`std::unordered_set`, not a quadratic
  scan) on both parse (`parser.cpp`) and serialize (`serializer.cpp`)
- stable parser and serializer error names
- signable object view scaffolding
- Matrix spec conformance fixture suites in `tests/conformance/`: room-version
  table, event graph, PDU format, redaction, and state resolution
- parser and serializer unit tests
- parser/serializer fuzz target

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
Unicode escape decoding, including surrogate-pair handling, is not
reimplemented in project code — it is delegated entirely to vendored `yyjson`;
`convert_yyjson_value()` (`src/canonicaljson/parser.cpp`) copies already-decoded
string bytes out of the `yyjson` document.

## Numeric policy

The strict signing parser (`parse_lossless()`) only accepts integers within
the JS-safe-integer range `[-(2^53)+1, (2^53)-1]`. Floating-point values,
exponent notation, and integers outside that range are rejected even though
`yyjson` can parse broader JSON number forms. This keeps Matrix signing
inputs lossless and deterministic. `is_canonical_int64_token()`
(`src/canonicaljson/parser.cpp`, around line 102) explicitly rejects negative
zero (`-0`, per the spec's "Numbers that are negative zero MUST NOT appear in
canonical JSON") and any leading-zero integer token (e.g. `01`) other than the
literal `0` itself; an explicit leading `+` sign is never seen by this
function at all, because the underlying `yyjson` read is strict RFC 8259
(`YYJSON_READ_NOFLAG`/`YYJSON_READ_NUMBER_AS_RAW`, no permissive extensions),
which already excludes a leading `+` from being tokenized as a number. The
separate general-purpose parser (`parse_json()`) accepts doubles and exponent
notation for payloads that are never signed.

The serializer mirrors this split: `serialize_canonical_strict()` rejects a
`Value` tree containing any double with `CanonicalJsonError::float_not_allowed`
instead of serializing it, and is the entry point `event_signer.cpp`,
`event_id.cpp`, and `signable.cpp` use for signing/hashing payloads.
`serialize_canonical()` still accepts floats — via a portable escalating-precision
`snprintf`/`strtod` round-trip search, not the fixed-precision `std::to_string`
formatting an earlier version used (`std::to_chars`'s floating-point overload
was considered but isn't implemented on every supported toolchain, e.g.
NetBSD's libstdc++ build only has the integer overloads) — because it is also
the general-purpose serializer for ordinary, never-signed JSON responses that
legitimately contain floats (e.g. `m.tag` `order`, account data). Because
`snprintf`/`strtod` both consult `LC_NUMERIC`, the formatter normalizes the
active locale's decimal separator back to `.` so float output stays valid
JSON even if some library calls `setlocale()` (#435).

## Signable object view

`make_signable_object_view` elides the top-level `signatures` and `unsigned`
keys (per the spec's Signing JSON procedure) and serializes the result with
`serialize_canonical_strict` — it is a signing-scoped entry point, so a
`Value` tree containing a float fails closed rather than being serialized.
Signing-key metadata layering remains future event-signing work.
