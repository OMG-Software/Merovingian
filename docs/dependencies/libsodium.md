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

LibSodium is available through the supported Linux and BSD package managers and
is required by the Meson build. The build wrappers check for the `libsodium`
pkg-config module before configuring Meson.

## Current limitations

- Runtime local signing-key materialization is deterministic scaffolding and
  must be replaced by a reviewed production key loader.
- Hardware-backed key storage remains future work.
