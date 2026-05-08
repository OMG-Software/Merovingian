# The Merovingian

Security-first Matrix homeserver written in modern C++26.

## Goals

- encrypted-by-default room policy
- hardened federation
- secure-by-default deployment
- protocol correctness
- high scalability without bypassing checks
- auditable operation

## Engineering rules

- RAII everywhere
- references preferred over pointers
- no raw owning pointers
- no naked allocation
- no custom cryptography
- security before performance
- all tests use Given/When/Then structure

## Build

```bash
meson setup build
meson compile -C build
meson test -C build
```

## Test standards

See:

- `docs/testing-standards.md`
- `security/coding-rules.md`

## Status

Early Phase 0 bootstrap implementation.
