# Phase 0 Checklist

Historical note: this checklist is retained as a snapshot of early bootstrap
work. Current progress is tracked in `docs/progress.md` and Matrix v1.18
coverage is tracked in `docs/protocol-coverage.md`.

## Build system

- [x] Meson bootstrap
- [x] Hardened compiler flags
- [x] Linux CI
- [x] BSD CI
- [x] Sanitizer CI
- [x] Static-analysis CI

## Security baseline

- [x] RAII wrappers
- [x] References preferred over pointers
- [x] No raw owning pointers
- [x] Unsafe allocation gates
- [x] Logging security rules
- [x] Threat model stub
- [x] SECURITY.md

## Testing

- [x] Catch2 integration
- [x] Given/When/Then testing standard
- [x] Unit test skeletons
- [x] Fuzz scaffolding

## Core infrastructure

- [x] SecretBuffer
- [x] FileDescriptor
- [x] SocketHandle
- [x] Error abstraction
- [x] Logging infrastructure
- [x] Config skeleton
- [x] HTTP skeleton

## Documentation

- [x] README bootstrap
- [x] Architecture document
- [x] Coding rules
- [x] Testing standards
