# src/canonicaljson/ — Canonical JSON Module

Implements the Matrix canonical JSON encoding used for signing and hashing.
Spec authority: ../../docs/matrix-v1.18-spec/appendices.md#canonical-json

## Key files

| File | Responsibility |
|---|---|
| `parser.cpp` | Parse JSON bytes into `Value` tree; validates structure and rejects non-canonical input |
| `serializer.cpp` | Serialize `Value` tree to canonical JSON bytes (sorted keys, no insignificant whitespace) |
| `signable.cpp` | Wraps a JSON object for signing — removes `signatures` and `unsigned` before hashing |
| `value.cpp` | `Value` variant type: null, bool, integer, float, string, array, object |
| `yyjson_adapter.c` | Thin C adapter over yyjson for raw parse speed |

## Canonical JSON rules (from spec)

- Keys in objects are sorted lexicographically by Unicode codepoint
- No insignificant whitespace
- Integers in the range `[-(2^53)+1, (2^53)-1]` only — no floats in signed/hashed data
- Strings are UTF-8 with only mandatory escape sequences (`\"`, `\\`, control chars)

## Critical constraints

- **Never sign or hash a string that was not produced by `serializer.hpp`.** Any other
  JSON library can produce non-canonical output that silently changes the hash.
- **Do not call the serializer on event objects before stripping `signatures` and `unsigned`.**
  Use `signable.hpp` which handles this correctly.
- The parser intentionally rejects duplicate keys — Matrix spec forbids them.

## Key spec sections

- [Canonical JSON](../../docs/matrix-v1.18-spec/appendices.md#canonical-json)
- [Signing JSON](../../docs/matrix-v1.18-spec/appendices.md#signing-json)
