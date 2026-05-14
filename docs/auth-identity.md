# Authentication and identity foundation

This capability note describes the authentication and identity policy boundary
used before full Matrix Client-Server login, registration, and device APIs are
production-gated.

## Included now

- Matrix-shaped user ID validation.
- Server-name validation for local identity handling.
- Device ID validation.
- Password policy shape for future local-password authentication.
- Account state model for active, locked, and suspended users.
- Login policy decisions that fail closed for invalid, locked, suspended, or password-disabled accounts.
- Access-token record shape bound to user and device identity.
- Token hash persistence validation.
- Token expiry and revocation policy decisions.
- Constant-time string comparison helper for token-hash checks.
- Token redaction helper for safe logs.
- Runtime-wired server-blind E2EE key API route shapes for device keys,
  one-time keys, fallback keys, cross-signing, signatures, and room-key backup
  routes.
- Durable E2EE storage for device keys, one-time keys, fallback keys,
  cross-signing keys, signatures, backup versions, and backup sessions.
- `/keys/query` returns persisted device keys, and `/keys/claim` consumes
  one-time keys before reusing fallback keys.
- Redacted key payload summaries in runtime records and audit events.
- Unit coverage for identity validation, account lock/suspension behavior, password policy, token activity, and log redaction.

## Security posture

The core auth policy module deliberately stays free of cryptographic password
hashing, token generation, and random number generation. The local homeserver
runtime now performs those operations through the reviewed LibSodium-backed
boundary rather than storing plaintext credentials or bearer tokens.

The boundary establishes these guarantees:

- Plaintext tokens are not a persistable representation.
- Token logging emits only redacted metadata.
- Revoked and expired tokens fail closed.
- Locked and suspended accounts cannot pass the login policy gate.
- Password login can be disabled per account.
- Device IDs reject whitespace/control-shaped values.
- Key API runtime records store route metadata and redacted payload summaries,
  not uploaded key material.
- Persisted key material is represented as server-blind sensitive JSON payloads
  and is not logged through prepared-statement summaries.

## Deliberately not included

These remain deferred:

- Full Matrix `/login`, `/logout`, `/register`, or device-management endpoint
  conformance.
- Refresh-token rotation.
- Access-token database persistence.
- Admin bootstrap flow.
- Registration token storage.
- Rate-limit integration.
- Audit-log persistence.
- Session invalidation.
- Device-list stream tokens and cross-device key update semantics.
- Complete backup retrieval/deletion semantics.

## Next starting points

1. Add a reviewed crypto dependency boundary for random token generation and password hashing.
2. Add Matrix device-list update stream semantics and full key-count responses.
3. Complete backup retrieval/deletion semantics.
4. Add conformance fixtures for login, registration, devices, and E2EE key APIs.
