# Login verification and account creation are one function each, shared by the Matrix routes and the OAuth pages

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5a of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The OAuth 2.0 login and account pages must check a password and create an account without issuing a Matrix session.
`POST /login` and `POST /register` already hold every check that makes those safe: the failed-login throttle, the
Argon2id admission slot, the lock release and re-validation around the hash, the dummy hash for an unknown user, the
account-state gates, the username checks, the registration policy and the registration token. How do the pages get
the same checks without a second copy that drifts?

## Decision Drivers

* A check added to one path and not the other is an authentication bypass.
* `POST /login` and `POST /register` must answer byte for byte as before; no check may be reordered or weakened.

## Considered Options

* One verification function and one account-creation function, called by both the Matrix routes and the pages
* The pages call `login_local_user` and `register_local_user` and throw the session away
* The pages carry their own copy of the checks

## Decision Outcome

Chosen option: one function each.

* `verify_login_credentials` (`AuthService.cpp`) is the password check of `login_local_user`, moved unchanged: log
  `login.started`; the throttle (a refusal costs no hash and is not a failure); an Argon2id slot (none is `busy`, not a
  failure); the stored hash or the dummy hash; the verification with `runtime.mutex` released; re-find the user and
  require its hash unchanged; on failure count it against the claimed user ID and audit `login.rejected`, on success
  clear this source's failures. `login_local_user` calls it, then `login_local_user_by_id` as before.
* `verify_password_login` is `verify_login_credentials` followed by `account_state_refusal`, the one account-state gate,
  which `complete_login` and `login_local_user_by_id` also call. The gate stays out of `verify_login_credentials`
  because `/login` applies it after its device checks (invalid device ID, cross-signing collision, device cap); moving
  it in front would change what `/login` answers when two refusals apply. `PasswordLoginVerification::Outcome`
  distinguishes exactly what `/login` does: verified, invalid login, throttled, busy, deactivated.
* `login_identifier_user_id` is the one normalisation of a typed identifier (`parse_login_body` uses it).
* `create_local_account` makes `/register`'s post-UIA username checks (not valid, reserved, an appservice's exclusive
  namespace or sender, with `/register`'s errcodes in `OperationResult::errcode`) and then `register_password_account`,
  the gates `register_local_user` always made, with the caller's client key given to the registration policy.
  `/register` calls it with `127.0.0.1`, the address it has always passed; `register_local_user` passes the same.
  Neither creates a device, a token or a session.

### Positive Consequences

* A check added to the shared function protects both surfaces; the pages cannot skip one.
* The existing login and registration tests prove the Matrix routes unchanged.

### Negative Consequences

* `/register` keeps judging the registration policy for the fixed address `127.0.0.1`; changing that is a behaviour
  change for its own branch.

## Pros and Cons of the Options

### Calling the session-issuing functions and discarding the session

* Good, because no code moves.
* Bad, because it creates a device and a token the user never sees, and a device past the cap refuses a valid login.

### A second copy in the page handlers

* Bad, because the two copies drift, and the drift is a bypass.

## Links

* Relates to [ADR-0246](0246-the-password-hashing-concurrency-cap-is-configurable.md)
