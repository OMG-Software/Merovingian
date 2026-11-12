# src/auth/ — Authentication Module

Handles user registration, login, session tokens, access tokens, and the client-facing key API.
Spec authority: ../../docs/matrix-v1.19-spec/client-server-api.md

## Key files

| File | Responsibility |
|---|---|
| `Session.cpp` | Registration policy (enabled, token required). Whether a session is live is decided by `find_session` and the `revoked` flag in `src/homeserver/AuthService.cpp`, not here |
| `Token.cpp` | Token hashing (`hash_access_token_v2/v3/v4`), constant-time comparison |
| `Identity.cpp` | Validation of user IDs, localparts, device IDs and server names; login policy |
| `Password.cpp` | Argon2id hashing and verification of passwords and registration tokens |
| `OidcDiscovery.cpp` | OIDC / RFC 8414 authorisation-server metadata built from `config::OidcConfig` |
| `FailureWindowTable.cpp` | `FailureWindowTable`: the bounded, time-ordered failure counters behind the failed-login throttle (100 000 entries, fixed-size BLAKE2b-256 keys via `make_failure_key`, O(1) expiry from the front, oldest evicted when full). Not thread-safe: the runtime mutex serialises it. Used for (account, source), per-account and (account, device) UIA counters |
| `KeyApi.cpp` | `/_matrix/client/v3/keys/upload`, `/query`, `/claim` — E2EE key management |

UIAA and `/whoami` are implemented in `src/homeserver/ClientServerRuntime.cpp`, not in this module.

## Security rules — non-negotiable

1. **Never log tokens or passwords.** Wrap in `SecretBuffer` from `core/SecretBuffer.hpp`.
2. **Always hash tokens before storing.** Store a token hash, never the raw token. Hashes are
   BLAKE2b (`crypto_generichash`): the `v2` scheme is unkeyed; `v3` and `v4` are keyed with
   `crypto::TokenHmacKey`, derived from the operator master key in `crypto/TokenKey.cpp`.
3. **Always compare tokens with constant-time equality.** Use `constant_time_equal()` from
   `crypto/ConstantTime.hpp`, never `==` or `memcmp`.
4. **Argon2id for password hashing.** Use `crypto_pwhash` with `OPSLIMIT_INTERACTIVE` and
   `MEMLIMIT_INTERACTIVE`. Never use SHA or bcrypt for passwords.
   The test binaries replace the cost at link time and refuse any other parameters, so changing these fails every
   test that registers or logs in; `tests/password_cost/` pins them (ADR-0510).
5. **Validate all user IDs** against the identifier grammar before accepting registration.
6. **Revocation is one-way.** Never restore a revoked token; revoke more narrowly instead
   (e.g. `revoke_tokens_for_user_except_device`). See ADR-0052.
   A revocation that spans several commits revokes first, verifies against the store, marks the
   in-memory sessions, and only then performs the step a repeat reports as "already done" (the
   device-row delete answers 404 when repeated): a failure must leave the call retryable, and a
   session is marked revoked only after the durable writes succeed (ADR-0407). An account's
   OpenID tokens are revoked with it (ADR-0408).

7. **Split identifiers on the FIRST `:`.** A user ID's, room ID's or alias's server name is
   everything after the first `:` (`user_id_server_name`, `identifier_server_name`): no localpart
   contains `:`, while a server name may (`host:port`). Never `rfind(':')` (security audit run-1).
8. **The server's own localparts are reserved.** `localpart_is_reserved` (today `remote-media`,
   the remote media cache owner, ADR-0178) is refused at every account-creation path as a name
   already taken. Add a localpart there before the server starts using it as an owner or sender.

## Argon2id admission and the runtime lock

Every Argon2id call a client request can reach is bounded by the one `HomeserverRuntime::argon2id_admission`
budget and runs with `runtime.mutex` released (AUTH-4): `/login`, ordinary and appservice registration
(`make_user`), the registration token check, `POST /account/password` (hashing the new password) and
the user-interactive-auth password check (`verify_local_user_password`). The order is fixed: cheap
refusals first, then `try_acquire()` (no slot is `429 M_LIMIT_EXCEEDED` with `retry_after_ms`, never a
failed attempt), then `RuntimeLockRelease` around only the hash, then re-take the lock and **re-validate
what the hash's use depends on** before acting: the username is still free (registration), the account
exists, its stored hash is the one snapshotted before the release and the access token is still valid
(password change, UIA check, login). Never keep a `LocalUser` pointer across the release; copy the hash
out first. A new Argon2id call site without all three (slot, released lock, re-validation) is the defect.
See `docs/auth-identity.md` "Argon2id admission".

## Failed-login throttle

Three `FailureWindowTable`s on `HomeserverRuntime` back it (AUTH-2, AUTH-10); the policy lives in
`src/homeserver/AuthService.cpp`. Never merge them: login failures keyed (account, source) and per
account must not be consulted by user-interactive-auth password checks, which have their own
(account, device) table, or any stranger can lock the owner out of changing their password. UIA
failures must not feed the login tables either. A successful login clears only the (account,
source) key, never the per-account ceiling. Keep the cap and the amortised-O(1) expiry: no code
path may scan a table. See `docs/auth-identity.md` "Failed-login throttle".

## Session lookup and retention

`LocalDatabase::sessions` is a `homeserver::SessionTable`: `find` narrows by an index of token-hash digests and then calls
the caller's predicate, which must compare the full hashes with `constant_time_equal` (rule 3). Never answer a lookup from
the index alone, never add a fall-back scan for a miss (an unknown token is the common attack), and change a session's
hash only through `set_access_token_hash`. The `retention-sweep` job erases sessions that can never authenticate again and
deletes their rows; it keeps a revoked refresh token of a live device until it expires so reuse is still detected, at most 32 per
device, and drops one whose device is gone (ADR-0488, ADR-0590).

`PersistentStore::access_tokens` and `refresh_tokens` are `database::CredentialTable`s with the same rule: a digest index
that narrows, every candidate confirmed with `constant_time_equal`, no fall-back scan. `SessionTable::erase_device` drops one
device's sessions through the (user ID, device ID) index; it moves the last session into each hole, so insertion order is
not kept after it. Do not write a loop over either table to find a token, a device's rows or a predecessor.

A login on a device the user already holds DELETES the device's earlier access and refresh rows (never revokes them: a
presented revoked refresh row is reuse and would end the replacing login) in the transaction that inserts the new row, then
calls `erase_device`; a refresh does the same for its access rows and evicts retired refresh rows past
`max_retired_refresh_tokens_per_device`, never an unrevoked one (ADR-0590). Any new path that mints a login token goes through
`store_device_and_access_token(..., true)`.

## Token lifecycle

```
register/login → generate opaque token → hash (BLAKE2b, keyed for v3/v4) → store hash in DB
client request → hash incoming token → look up / constant-time compare with stored hash → grant/deny
logout → revoke the stored hash
```

Token bytes come from `crypto/Random.hpp`. Tokens are never stored or logged in plaintext.

## UIAA (User-Interactive Authentication)

UIAA session state is held **in memory** in the client-server runtime (`uia_sessions` in
`src/homeserver/ClientServerRuntime.cpp`), not in a database table. Sessions expire after 10 minutes
and are capped at `max_uia_sessions` (2048); each owner holds at most 16 and a full pool refuses a new challenge with 429 rather than evicting another owner (ADR-0683). Each flow has exactly one stage, so there is no stage list to
consult; adding a second stage would need persisted stage tracking. See ADR-0057.

## Login tokens (CS8, ADR-0548)

`POST /v1/login/get_token` (off unless `security.login_token.enabled`) asks for the account password on every call,
then mints a token held only as a hash in `ClientServerRuntime::login_tokens` (`LoginTokenStore`). `POST /login`
with `type: m.login.token` redeems it (constant-time, single use, spent by any attempt) and then goes through
`login_local_user_by_id`, so the deactivated/locked/suspended gate is shared with password login. Never persist these
tokens or add a path that redeems one without consuming it.
A path that revokes all of a user's sessions (`logout/all`, password change or reset with `logout_devices`, either
deactivation) must also call `login_tokens.erase_user` after the revocation succeeded (F-07).

## Key spec sections

- [Client Authentication](../../docs/matrix-v1.19-spec/client-server-api.md#client-authentication)
- [Registration](../../docs/matrix-v1.19-spec/client-server-api.md#account-registration)
- [Login](../../docs/matrix-v1.19-spec/client-server-api.md#login)
- [Key management](../../docs/matrix-v1.19-spec/client-server-api.md#end-to-end-encryption)
- [Identifier Grammar](../../docs/matrix-v1.19-spec/appendices.md#identifier-grammar)
