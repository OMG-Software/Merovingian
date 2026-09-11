# src/auth/ — Authentication Module

Handles user registration, login, session tokens, access tokens, and the client-facing key API.
Spec authority: ../../docs/matrix-v1.19-spec/client-server-api.md

## Key files

| File | Responsibility |
|---|---|
| `client_server_api.cpp` | Registration, login and logout routing and policy |
| `session.cpp` | Client-auth endpoint policy: which endpoints need an access token or mutate a session, registration policy, session-active decisions, audit-event construction |
| `token.cpp` | Token entropy checks, token hashing (`hash_access_token_v2/v3/v4`), constant-time comparison, log redaction |
| `identity.cpp` | Validation of user IDs, localparts, device IDs and server names; login policy |
| `password.cpp` | Argon2id hashing and verification of passwords and registration tokens |
| `oidc_discovery.cpp` | OIDC / RFC 8414 authorisation-server metadata built from `config::OidcConfig` |
| `key_api.cpp` | `/_matrix/client/v3/keys/upload`, `/query`, `/claim` — E2EE key management |

UIAA and `/whoami` are implemented in `src/homeserver/client_server.cpp`, not in this module.

## Security rules — non-negotiable

1. **Never log tokens or passwords.** Wrap in `SecretBuffer` from `core/secret_buffer.hpp`.
2. **Always hash tokens before storing.** Store a token hash, never the raw token. Hashes are
   BLAKE2b (`crypto_generichash`): the `v2` scheme is unkeyed; `v3` and `v4` are keyed with
   `crypto::TokenHmacKey`, derived from the operator master key in `crypto/token_key.cpp`.
3. **Always compare tokens with constant-time equality.** Use `constant_time_equal()` from
   `crypto/constant_time.hpp`, never `==` or `memcmp`.
4. **Argon2id for password hashing.** Use `crypto_pwhash` with `OPSLIMIT_INTERACTIVE` and
   `MEMLIMIT_INTERACTIVE`. Never use SHA or bcrypt for passwords.
5. **Validate all user IDs** against the identifier grammar before accepting registration.
6. **Revocation is one-way.** Never restore a revoked token; revoke more narrowly instead
   (e.g. `revoke_tokens_for_user_except_device`). See ADR-0052.

## Token lifecycle

```
register/login → generate opaque token → hash (BLAKE2b, keyed for v3/v4) → store hash in DB
client request → hash incoming token → look up / constant-time compare with stored hash → grant/deny
logout → revoke the stored hash
```

Token bytes come from `crypto/random.hpp`. Tokens are never stored or logged in plaintext.

## UIAA (User-Interactive Authentication)

UIAA session state is held **in memory** in the client-server runtime (`uia_sessions` in
`src/homeserver/client_server.cpp`), not in a database table. Sessions expire after 10 minutes
and are capped at 512 entries. Each flow has exactly one stage, so there is no stage list to
consult; adding a second stage would need persisted stage tracking. See ADR-0057.

## Key spec sections

- [Client Authentication](../../docs/matrix-v1.19-spec/client-server-api.md#client-authentication)
- [Registration](../../docs/matrix-v1.19-spec/client-server-api.md#account-registration)
- [Login](../../docs/matrix-v1.19-spec/client-server-api.md#login)
- [Key management](../../docs/matrix-v1.19-spec/client-server-api.md#end-to-end-encryption)
- [Identifier Grammar](../../docs/matrix-v1.19-spec/appendices.md#identifier-grammar)
