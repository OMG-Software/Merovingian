# src/auth/ — Authentication Module

Handles user registration, login, session tokens, access tokens, and the client-facing key API.
Spec authority: ../../docs/matrix-v1.18-spec/client-server-api.md

## Key files

| File | Responsibility |
|---|---|
| `client_server_api.cpp` | Registration, login, logout, UIAA flow, whoami |
| `session.cpp` | Session creation, lookup, and expiry |
| `token.cpp` | Access-token generation, hashing (SHA-256 via `crypto_generichash`), and validation |
| `identity.cpp` | User ID construction and validation |
| `key_api.cpp` | `/_matrix/client/v3/keys/upload`, `/query`, `/claim` — E2EE key management |

## Security rules — non-negotiable

1. **Never log tokens or passwords.** Wrap in `SecretBuffer` from `core/secret_buffer.hpp`.
2. **Always hash tokens before storing.** Store `crypto_generichash(token)`, never the raw token.
3. **Always compare tokens with constant-time equality.** Use `constant_time_equal()` from
   `crypto/constant_time.hpp`, never `==` or `memcmp`.
4. **Argon2id for password hashing.** Use `crypto_pwhash` with `OPSLIMIT_INTERACTIVE` and
   `MEMLIMIT_INTERACTIVE`. Never use SHA or bcrypt for passwords.
5. **Validate all user IDs** against the identifier grammar before accepting registration.

## Token lifecycle

```
register/login → generate opaque token → crypto_generichash → store hash in DB
client request → hash incoming token → constant-time compare with stored hash → grant/deny
logout → delete hash from DB
```

Token bytes come from `crypto/random.hpp`. Tokens are never stored or logged in plaintext.

## UIAA (User-Interactive Authentication)

Some endpoints require UIAA. The flow is stateless across requests; session state is held in the
`auth_sessions` table. Always check the UIAA stage list from config before accepting an auth attempt.

## Key spec sections

- [Client Authentication](../../docs/matrix-v1.18-spec/client-server-api.md#client-authentication)
- [Registration](../../docs/matrix-v1.18-spec/client-server-api.md#account-registration-and-management)
- [Login](../../docs/matrix-v1.18-spec/client-server-api.md#login)
- [Key management](../../docs/matrix-v1.18-spec/client-server-api.md#end-to-end-encryption)
- [Identifier Grammar](../../docs/matrix-v1.18-spec/appendices.md#identifier-grammar)
