# yyjson dependency review

This note records the dependency review for yyjson.

## Decision

yyjson is accepted as the strict JSON parser dependency behind the
`merovingian::canonicaljson` adapter. Project C++ sources must include the
project-owned adapter instead of including `yyjson.h` directly.

## Why it is needed

Matrix event IDs, hashes, and signatures depend on deterministic JSON handling.
Using yyjson avoids a project-local parser while still allowing Merovingian to
copy parsed values into project-owned canonical JSON value types.

## Security boundary

- yyjson documents are freed through the C adapter before data leaves the parser
  implementation.
- Parsed values are copied into Merovingian value objects before higher-level
  event, federation, or homeserver code sees them.
- The adapter maps yyjson parse errors into stable project parse errors.
- The pinned wrap exposes third-party headers as system includes to keep
  warning-as-error focused on project code.

## Maintenance and platform posture

Meson first attempts a system `yyjson` dependency and falls back to the pinned
wrap when the host does not provide one. The wrap is intentionally isolated to
the canonical JSON module.

## Current limitations

- Full Matrix conformance fixtures still need to expand around canonical JSON
  edge cases.
