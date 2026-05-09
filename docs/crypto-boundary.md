# Milestone 7: Cryptography boundary and signing service scaffold

Milestone 7 introduces project-owned cryptography interfaces without implementing custom cryptographic primitives.

## Included in Milestone 7

- Constant-time comparison boundary.
- Random-source interface for future reviewed RNG integration.
- Ed25519 provider interface for future reviewed signing and verification integration.
- Server signing-key store interface.
- Server signing-service scaffold that selects the active server key and delegates signing to a provider.
- Validation for Ed25519 public-key shape, signature shape, and key IDs.
- Bounded random request-size validation.
- Unit tests using deterministic test doubles.

## Security posture

This milestone intentionally does not implement Ed25519, token generation, password hashing, or random byte generation. Those must be supplied by reviewed cryptographic dependencies through these interfaces.

The boundary provides these guarantees:

- Application code depends on project-owned interfaces, not dependency-specific types.
- Signing fails closed when no active usable key exists.
- Providers returning invalid signature shapes are rejected.
- Key IDs must be Ed25519-shaped before use.
- Random byte requests are bounded at the interface edge.

## Deliberately not included

These are deferred to later milestones:

- libsodium or TLS-provider integration.
- Real Ed25519 signing and verification.
- Password hashing implementation.
- Random token generation implementation.
- Server signing-key persistence.
- Signing-key rotation and audit-log persistence.
- Hardware-backed key support.

## Next starting points

1. Add dependency review documentation for the selected crypto provider.
2. Add a concrete provider behind the Ed25519 and RNG interfaces.
3. Add database-backed signing-key persistence.
4. Integrate event signing with the signing-service boundary.
5. Add audit events for signing-key lifecycle changes.
