# Milestone 6: Authentication and identity foundation

Milestone 6 introduces the narrow authentication and identity policy boundary needed before adding Matrix Client-Server login, registration, and device APIs.

## Included in Milestone 6

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
- Unit coverage for identity validation, account lock/suspension behavior, password policy, token activity, and log redaction.

## Security posture

The auth module deliberately does not implement cryptographic password hashing, token generation, or random number generation. Those must come from reviewed external cryptographic primitives through the future crypto boundary.

The milestone establishes these guarantees:

- Plaintext tokens are not a persistable representation.
- Token logging emits only redacted metadata.
- Revoked and expired tokens fail closed.
- Locked and suspended accounts cannot pass the login policy gate.
- Password login can be disabled per account.
- Device IDs reject whitespace/control-shaped values.

## Deliberately not included

These are deferred to later milestones:

- Matrix `/login`, `/logout`, `/register`, or device-management endpoints.
- Password hashing implementation.
- Token generation implementation.
- Refresh-token rotation.
- Access-token database persistence.
- Admin bootstrap flow.
- Registration token storage.
- Rate-limit integration.
- Audit-log persistence.
- Session invalidation.
- Cross-signing or key APIs.

## Next starting points

1. Add a reviewed crypto dependency boundary for random token generation and password hashing.
2. Add database persistence interfaces for users, devices, token hashes, and audit events.
3. Add Client-Server auth endpoint scaffolding behind HTTP route dispatch.
4. Add rate-limit hooks for login, registration, and device APIs.
