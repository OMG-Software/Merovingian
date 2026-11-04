# OpenID tokens end with the credentials they were minted from

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, finding F-77.

## Context and Problem Statement

An OpenID token minted by `POST /user/{userId}/openid/request_token` lives for an
hour in the `openid_tokens` table. Deactivation, logout everywhere and a password
change left the rows in place, and `federation_openid_userinfo` named the user for
any matching unexpired row without looking at the account. The unauthenticated
`GET /_matrix/federation/v1/openid/userinfo` therefore kept asserting a
deactivated account to third parties for up to an hour. The spec does not require
OpenID tokens to be revoked.

## Decision Drivers

* The project's own policy, stated in `deactivate_local_user`: every credential
  dies with the account.
* [ADR-0031](0031-store-narrow-purpose-tokens-in-separate-tables.md): OpenID
  tokens must never be readable by, or mixed into, the access-token paths.

## Considered Options

* Delete the user's rows from `openid_tokens` in the revocation paths, and have
  userinfo refuse a missing or deactivated user
* Only make userinfo check the account's state
* Mark OpenID tokens revoked through the access-token tables

## Decision Outcome

Chosen option: "delete in the revocation paths, and check the account in userinfo".
`database::revoke_openid_tokens_for_user` removes the user's rows from the backend
and the in-memory list. `deactivate_local_user`, `logout_all_local_user` and
`change_local_user_password` with `logout_devices` call it and fail with 500 if it
fails. `federation_openid_userinfo` additionally returns nothing for a user that is
missing or deactivated, which also covers a token minted in the moment before a
deactivation. A password change that keeps other devices (`logout_devices=false`)
leaves OpenID tokens alone. OpenID tokens are not tied to a device, so a
password change that logs out other devices ends all of the user's tokens,
including the caller's own.

The helper returns `bool` where the access-token helpers return a row count
([ADR-0116](0116-verify-token-revocation-state-in-auth-service.md)): a delete has
no count that could be mistaken for a failure, because the only answer a caller
needs is "none left".

### Negative Consequences

* A relying party that holds a token loses it when the user changes their password
  or logs out everywhere, and the client must request a new one.

## Pros and Cons of the Options

### Delete and check the account

* Good, because the row is gone from the table and the lookup is safe even if one
  is restored.
* Good, because it keeps the separation of ADR-0031: only the OpenID table and the
  user record are read.

### Check the account only

* Good, because it is small.
* Bad, because logout everywhere and a password change would still leave the
  token valid for an active account.

### Reuse the access-token revocation tables

* Bad, because it ties OpenID tokens to the access-token store, which is what
  ADR-0031 exists to prevent.

## Links

* Refines [ADR-0031](0031-store-narrow-purpose-tokens-in-separate-tables.md)
