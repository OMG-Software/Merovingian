# An OAuth sign-in carries the credential stamp of its password check and ends when it changes

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: review finding 1 on `feature/oauth-20-v110`.

## Context and Problem Statement

A sign-in on `/_merovingian/oauth2/authorize` checks the password once and records the user on the pending entry.
Everything after that trusts the record: the consent page's `approve` (ten minutes later at most), the authorization
code it mints (60 seconds), the device grant's approval and the poll that collects it, and the legacy hand-off's
confirmation. `account_sign_in_gate` at those steps refuses a deactivated or locked account, but not one whose password
changed. Someone who knows a user's password can therefore sign in and wait; when the user changes or resets the
password because of exactly that, the attacker still gets a code, tokens or a login token. How does a sign-in in
progress learn that the credential it checked is no longer the account's?

## Decision Drivers

* Every password change, reset and deactivation must end every sign-in in progress, without each of those paths
  having to know about the OAuth stores (four paths today, and every future one).
* The value kept in the stores and compared must not reveal the password or its stored hash if a store's memory or a
  log leaked, and must never be logged.
* A sign-in with no change in between must still work.

## Considered Options

* A credential stamp derived from the stored password hash, recorded when the password is verified or the account
  created, and compared at every later step.
* Have every password change walk the pending, code and device stores and end the user's entries.
* A per-user generation counter, bumped by every password change.

## Decision Outcome

Chosen option: the credential stamp. `user_credential_stamp` (`AuthService.cpp`, the one place it is computed) is
`oauth_secret_hash` of the user's stored password hash, compared with `user_credential_stamp_matches` in constant time.
Every write of a password hash (change, email reset, account page, deactivation's `!deactivated`) stores a new
Argon2id string (`crypto_pwhash_str`) with a fresh random salt, so the stamp changes with it, and nothing has to remember to bump it. The
stored hash carries a 128-bit salt and a 256-bit tag, so its unkeyed BLAKE2b hash cannot test a password guess or be
reversed; the stamp is never logged and never leaves the process.

It is recorded by `PendingAuthorisationStore::record_user`, taken in the same hold of `runtime.mutex` in which
`verify_password_login` confirmed the stored hash (or `create_local_account` wrote it), and carried into
`AuthorizationGrant::credential_stamp` and, through `DeviceAuthorisationStore::decide`, into the device authorisation's
approval. It is checked at `approve` for all three kinds of entry (an authorisation code, a device sign-in, the legacy
hand-off's confirmation), and at the token endpoint after `account_sign_in_gate` for the code grant and the device-code
grant. A mismatch is the expired page on a page (the entry is already consumed; a device sign-in releases its hold on
the device authorisation) and `invalid_grant` at the token endpoint (the code or device code is already spent). The
consent page is rendered in the same hold of the lock that recorded the stamp, so it needs no check of its own.

### Positive Consequences

* A password change ends an attacker's sign-in in progress whichever path changed it, including paths added later.
* The stores hold a value that is useless if leaked.

### Negative Consequences

* A sign-in started just before the user changed their own password must be started again.

## Pros and Cons of the Options

### Walk the stores on every password change

* Bad, because each password path must call it, and a forgotten path is a silent hole.
* Bad, because the stores live in two runtimes (the code and device stores in `HomeserverRuntime`, nothing in the
  pending store indexes by user), so it costs a scan.

### A generation counter

* Good, because it is cheap to compare.
* Bad, because it is new persistent state every password writer must bump; the stored hash already changes.

## Links

* Builds on [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md)
  and [ADR-0783](0783-login-verification-and-account-creation-are-one-function-each-shared-by-the-matrix-routes-and-the-oauth-pages.md)
