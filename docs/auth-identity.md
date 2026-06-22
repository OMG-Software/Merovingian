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
- Login policy decisions that fail closed for invalid, locked, or password-disabled accounts; suspended accounts MAY still log in per spec v1.18 §"Account suspension" (the new session is itself suspended and enforced by the request-path gate).
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
- Client-server registration, password login, refresh-token rotation, logout,
  global logout, whoami, device listing, single-device fetch, device update,
  and device delete routes use runtime token validation.
- Account 3PID email and MSISDN flows are implemented for the local account
  surface: unauthenticated `requestToken` endpoints issue validation sessions,
  `POST /account/3pid/add` enforces password UIA, the deprecated
  `POST /account/3pid` association route is accepted, and the bind/list/unbind/
  delete endpoints maintain per-account 3PID records including
  `added_at` / `validated_at` metadata.
- Access-token hashes are durable and hydrate back into runtime sessions after
  restart.
- Refresh-token hashes are persisted, rotated, and revoked on global logout,
  device deletion, or password change with `logout_devices: true` (spec default)
  without storing plaintext token material; the caller's own device is preserved.
- Account lock/suspend admin endpoints `GET/PUT /_matrix/client/v1/admin/lock/{userId}`
  and `/_matrix/client/v1/admin/suspend/{userId}` (admin-gated, anti-enumeration,
  locality and self/other-admin guards) set the persisted and in-memory account
  state. The request path enforces spec semantics without revoking sessions: a
  locked account gets `401 M_USER_LOCKED` with `soft_logout: true` on all
  endpoints except `/logout` and `/logout/all`; a suspended account gets
  `403 M_USER_SUSPENDED` on actions outside the spec allowlist. Locked takes
  precedence over suspended.
- Login failures for unknown users, wrong passwords, and locked accounts
  collapse to the same external `invalid login` result while still recording
  the internal rejection reason in audit logs.
- Newly issued access and refresh tokens are persisted as keyed
  `token-hash:v3:` digests derived from runtime secret material; token lookup
  still accepts legacy `token-hash:v2:` rows during migration.
- Client-server auth/device/key actions append durable audit rows without
  logging plaintext credentials, bearer tokens, or key payloads.
- Unit coverage for identity validation, account lock/suspension behavior, password policy, token activity, and log redaction.
- Registration token verification using Argon2id (`crypto_pwhash_str` / `crypto_pwhash_str_verify`);
  only the password hash is retained, and the plaintext token is zeroised after hashing. The
  `GET /_matrix/client/v1/register/m.login.registration_token/validity` endpoint verifies the
  candidate through the same Argon2id hash (`registration_token_matches`) rather than comparing
  plaintext, so the token material never sits on the request path.
- Server-side access and refresh token expiry is enforced. `PersistentAccessToken`,
  `PersistentRefreshToken`, and `LocalSession` carry an `expires_at` field set at issuance from
  configurable `security.access_token_lifetime_ms` (default 1h) and
  `security.refresh_token_lifetime_ms` (default 30d); `0` disables expiry for that kind.
  `find_session` and the refresh-token lookup reject expired tokens (failing closed toward
  re-login/refresh) even when the session is not revoked, and the advertised `expires_in_ms`
  reads from the configured access-token lifetime so advertised == enforced. Legacy/no-expiry
  rows (`expires_at` empty / `nullopt`) remain valid.
- Token-hash lookups route through constant-time comparison (`crypto::constant_time_equal` /
  `auth::constant_time_equal`, backed by `sodium_memcmp`) on every fixed-length hash match —
  the access/refresh store lookups and the in-memory session match — not just the canonical
  policy helper.

## Security posture

The core auth policy module deliberately stays free of cryptographic password
hashing, token generation, and random number generation. The local homeserver
runtime now performs those operations through the reviewed LibSodium-backed
boundary rather than storing plaintext credentials or bearer tokens.

The boundary establishes these guarantees:

- Plaintext tokens are not a persistable representation.
- Token logging emits only redacted metadata.
- Revoked and expired tokens fail closed. Server-side token expiry is enforced on
  both access and refresh tokens via the configurable lifetimes above, distinct from
  revocation: an expired-but-not-revoked session is rejected with audit reason
  `token expired`.
- Locked accounts cannot pass the login policy gate; suspended accounts may
  still log in, and their new session is itself suspended and gated by the
  request-path `M_USER_SUSPENDED` check.
- Password login can be disabled per account.
- Device IDs reject whitespace/control-shaped values.
- Key API runtime records store route metadata and redacted payload summaries,
  not uploaded key material.
- Persisted key material is represented as server-blind sensitive JSON payloads
  and is not logged through prepared-statement summaries.
- Registration tokens are verified with Argon2id and only the hash is retained;
  plaintext tokens are zeroised with `sodium_memzero` after hashing.

## Deliberately not included

These remain deferred:

- Full Matrix UI-auth fallback flows and account recovery endpoints.
- Admin bootstrap flow.
- Rate-limit integration.
- Device-list stream tokens and cross-device key update semantics.
- Complete backup retrieval/deletion semantics.

## Next starting points

1. Add a reviewed crypto dependency boundary for random token generation and password hashing.
2. Add Matrix device-list update stream semantics and full key-count responses.
3. Complete backup retrieval/deletion semantics.
4. Extend conformance fixtures beyond the beta auth/device/key happy paths into
   UI auth, interactive auth, and negative-device-list cases.

- /keys/upload validates that every one-time and fallback key carries a signature by the device's own ed25519 identity key, rejecting unverifiable keys with 400 M_INVALID_SIGNATURE. This prevents stale device rows from leaving behind SignedKeys that no peer can verify at /keys/claim time, which would block the Olm session for the whole room's Megolm distribution.
- /keys/query returns persisted device keys, and /keys/claim consumes
