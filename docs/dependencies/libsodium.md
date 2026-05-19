# LibSodium dependency review

This note records the dependency review for LibSodium.

## Decision

LibSodium is accepted as the runtime cryptography dependency for password
hashing, random token generation, content digests, Matrix event hashes, and
Ed25519 signing support. It must remain behind project-owned crypto, media,
event, and homeserver boundaries.

## Why it is needed

Merovingian must not carry project-local cryptographic primitives. LibSodium
provides reviewed primitives for hashing, password storage, random generation,
and Ed25519 operations across Linux and BSD package managers.

## Security boundary

- Password hashing and token generation flow through Merovingian auth helpers.
- Event hashing and signing use project event APIs rather than direct sodium
  calls from handlers.
- Media digests are calculated through the media repository boundary.
- Sodium initialization is checked before cryptographic operations proceed.
- Raw sodium key material must not be logged or stored outside explicit key
  storage records.

## Maintenance and platform posture

LibSodium is resolved from the operating-system package and linked dynamically.
The top-level Meson dependency sets `allow_fallback: false`, so clean builds
must provide `libsodium.pc` through the host package manager even when the
wrapper scripts use Meson's `forcefallback` mode for other dependencies.

Supported development paths install the OS development package explicitly:
Debian-family hosts use `libsodium-dev`, Fedora-family hosts use
`libsodium-devel`, FreeBSD uses `libsodium`, OpenBSD uses `libsodium`, and
NetBSD/pkgsrc uses `libsodium`.

## Current limitations

- Runtime local signing-key materialization is deterministic scaffolding and
  must be replaced by a reviewed production key loader.
- Hardware-backed key storage remains future work.
