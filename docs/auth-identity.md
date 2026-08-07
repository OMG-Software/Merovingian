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
- Login policy decisions that fail closed for invalid, locked, or password-disabled accounts; suspended accounts MAY still log in per spec v1.19 §"Account suspension" (the new session is itself suspended and enforced by the request-path gate).
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
- `POST /refresh` does not require access-token authentication — spec: "this
  endpoint does not require authentication via an access token. Authentication
  is provided via the refresh token." `client_auth_endpoint_requires_access_token`
  excludes `login`, `register_account`, and `refresh_token`.
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
- Newly issued access and refresh tokens are persisted as keyed digests derived
  from the operator's master key file via domain-separated BLAKE2b. With a master
  key configured, issuance uses the `token-hash:v4:` scheme; the legacy
  `token-hash:v3:` scheme is retained only for validation and is itself now
  master-key-derived (distinct domain separator `merovingian:access-token-hmac:legacy-v3:1`)
  — it is no longer backed by the Ed25519 signing seed (issue #322, cryptographic
  key separation). **Breaking (v0.10.9):** pre-#322 `token-hash:v3:` hashes were
  derived from the Ed25519 signing seed and no longer validate under the new
  master-key-derived v3 key; affected sessions fail closed and must re-login,
  after which they are issued v4 tokens. Without a master key configured, both
  v3 and v4 are unavailable and issuance falls back to the unkeyed
  `token-hash:v2:` hash so local operations keep working — configure a master
  key for hardened token hashing (the federation worker already requires one).
  **(issue #436)** Every time a new token is issued under this fallback, a
  `token.unkeyed_hash_fallback` diagnostic is logged at `warning` so operators
  notice the degraded mode instead of discovering it in a post-breach audit
  (a DB leak of unkeyed v2 hashes is offline-brute-forceable).
- `redacted_token_for_log()` (issue #437) discloses only a coarse size bucket
  (`tiny`/`short`/`medium`/`long`), never the exact byte length — the precise
  length was a minor side channel that let an observer of logs distinguish
  token versions and valid- from invalid-length presented tokens.
- Client-server auth/device/key actions append durable audit rows without
  logging plaintext credentials, bearer tokens, or key payloads.
- `GET /_matrix/client/v1/auth_metadata` (MSC2965 OIDC discovery) returns RFC 8414 / Matrix v1.19 authorisation server metadata when `server.oidc.*` is configured; returns `404 M_UNRECOGNIZED` when OIDC is not configured. No OAuth 2.0 authorization-code / token / revocation flow is implemented yet.
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
- Device-list stream tokens and cross-device key update semantics: `build_device_list_arrays()`
  populates `/sync`'s `device_lists.changed`/`left` from `store.device_list_changes` filtered
  by `since_sync_stream_id`, and `broadcast_device_list_updates()` emits `m.device_list_update`
  EDUs on cross-signing/key changes. Per-algorithm `device_one_time_keys_count` is wired into
  `/sync` as well. A `device_lists.changed` self-notification is recorded at two trigger points
  so a user's own devices discover each other without relying on room co-membership: on
  `POST /_matrix/client/v3/keys/upload` (key upload) and on `POST /_matrix/client/v3/login`
  when a genuinely new device is created. The login trigger ensures a freshly-logged-in
  device's initial `/sync` lists its own user in `device_lists.changed`, prompting it to
  `/keys/query` and fetch the user's *existing* devices' keys before any
  `m.key.verification.request` can arrive — closing the cross-device verification gap where
  the new device otherwise dropped the request for lack of the sender's device keys.
- Key-backup retrieval and deletion: `handle_key_api_route()` implements
  `get_key_backup_version`, `get_key_backup_version_by_id`, `get_room_key_backup`
  (session/room/batch), `get_room_key_backup_batch`, `delete_room_key_backup`,
  `delete_room_key_backup_room`, and `delete_room_key_backup_batch`, all reading/writing real
  session rows from `persistent_store.key_backup_sessions`.

## Identity server client (3PID invites)

A dedicated `identity` module (`include/merovingian/identity/identity_client.hpp`,
`src/identity/identity_client.cpp`) owns the outbound Identity Service API client.
`IdentityServerClient` exposes `store_invite`, `lookup`, `bind`, `unbind`, and
`requestToken` methods plus pure helpers (`parse_identity_server_url`,
`build_*_body`, `parse_store_invite_response`, `parse_lookup_response`). It talks
to a remote identity server over `http::OutboundClient` combined with
`federation::CachedServerDiscovery`, and is SSRF-safe: resolved addresses are
pinned and private/loopback ranges are rejected via `deny_ip_ranges`.

The homeserver is a **client** of the identity server, not a federation peer:
authentication uses a bearer `id_access_token` supplied by the calling client,
never `X-Matrix`. See spec v1.19 Identity Service API.

`POST /_matrix/client/v3/rooms/{roomId}/invite` with `id_server`/`medium`/
`address`/`id_access_token` now delegates token and key generation to the IS via
`store-invite` and builds the `m.room.third_party_invite` event from the
IS-issued token (used as the `state_key`) plus the IS's ephemeral public key
(top-level `public_key`/`key_validity_url`) and the full `public_keys` array.
Per spec v1.19 client-server-api §"Third-party invites" and the
`SignedThirdPartyInvite` shape, the token MUST be issued by the identity server
at `/store-invite`: the join-side `third_party_signed` signature is verified
against the IS's key, so the previous local-only token minting was
non-conformant. The HS fails closed with `403 M_FORBIDDEN` when the supplied
`id_server` is not listed in `server.identity_server.trusted_servers`, and
returns `502` on transport error or a malformed IS response.

The `server.identity_server.*` config block (`trusted_servers`,
`default_server`, `allowed_bind_domains`, `connect_timeout_seconds`,
`total_timeout_seconds`) is hot-reloaded and marked restart-required for
trust-set changes. 3PID bindings are persisted via migration
`006_account_threepids.sql` (previously in-memory).

**Deferred follow-on:** the `bind`, `unbind`, and `requestToken` handlers
persist locally but do not yet drive the remote IS; that sync is deferred pending
a discovery test-seam for hermetic IS mocking.

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

## Next starting points

1. Add a reviewed crypto dependency boundary for random token generation and password hashing.
2. Extend conformance fixtures beyond the beta auth/device/key happy paths into
   UI auth, interactive auth, and negative-device-list cases.

`/keys/upload` validates that every one-time and fallback key carries a signature by the
device's own Ed25519 identity key, rejecting unverifiable keys with `400 M_INVALID_SIGNATURE`.
This prevents stale device rows from leaving behind signed keys that no peer can verify at
`/keys/claim` time, which would block the Olm session for the whole room's Megolm distribution.
