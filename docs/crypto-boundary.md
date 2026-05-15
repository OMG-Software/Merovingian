# Cryptography boundary and signing service scaffold

This capability note describes project-owned cryptography interfaces without
implementing custom cryptographic primitives.

## Included now

- Constant-time comparison boundary.
- Random-source interface for future reviewed RNG integration.
- Ed25519 provider interface for reviewed signing and verification integration.
- Server signing-key store interface.
- Server signing service that selects the active server key and delegates
  signing to a provider.
- Runtime server signing-key persistence for the current local Ed25519 key.
- Validation for Ed25519 public-key shape, signature shape, and key IDs.
- Bounded random request-size validation.
- Event-signing integration tests using deterministic provider doubles.

## Security posture

Local homeserver password hashing, access-token generation, access-token
hashing, media deduplication hashes, and Matrix event hashes use LibSodium.
Event signing and verification now flow through the Ed25519 provider interface.
Runtime-created local room events use the persisted server signing-key record
and fail closed if the signing key cannot be materialized.

The boundary provides these guarantees:

- Application code depends on project-owned interfaces, not dependency-specific types.
- Signing fails closed when no active usable key exists.
- Providers returning invalid signature shapes are rejected.
- Key IDs must be Ed25519-shaped before use.
- Matrix event signatures are encoded as unpadded Base64 and verified against
  the redacted canonical payload.
- Runtime event signatures are stored with event rows and the corresponding
  public signing key is persisted for local verification/key publication work.
- Random byte requests are bounded at the interface edge.

## Deliberately not included

These remain deferred:

- Signing-key rotation and audit-log persistence.
- Hardware-backed key support.

## Next starting points

1. Add dependency review documentation for the selected crypto provider.
2. Add a concrete production provider behind the Ed25519 and RNG interfaces.
3. Replace the deterministic local runtime key materialization with a reviewed
   production key loader.
4. Add audit events for signing-key lifecycle changes.
