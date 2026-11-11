# A deactivated account's access token is an unknown token

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-authn.session-gate.no-deactivated-check-on-access-token`.

## Context and Problem Statement

Deactivation sets `deactivated`, then revokes the account's credentials. If a revocation write fails the call answers 500
and the in-memory sessions stay live, so until a retry completes, the access-token gate (`authenticated_user`,
`authenticated_session`) accepted a token of a closed account. Login, refresh and OpenID userinfo each already refuse a
deactivated account. What does the access-token gate answer?

## Considered Options

* Refuse in `authenticated_user` and `authenticated_session` as an unknown token (`nullopt`, so 401 `M_UNKNOWN_TOKEN`).
* Refuse as 403 `M_USER_DEACTIVATED`, as login does.
* Leave the gate and rely on the retry.

## Decision Outcome

Chosen option: the first. Both functions return `nullopt` for a session whose user is deactivated, so every caller of the
gate (`require_admin`, `authenticated_admin_user`, the dispatcher and every service that takes a token) refuses with the
answer it already gives an unknown token.

Login answers 403 because a person is presenting a password and is told why. A token of a closed account is a credential
that no longer exists: the spec's answer for a token the server does not know is 401 `M_UNKNOWN_TOKEN`, and it tells the
holder of a stolen token nothing about the account. A 403 would also let a client treat the failure as retryable rather
than as the end of the session.

### Negative Consequences

* A user whose deactivation answered 500 cannot retry it with their own token; an administrator completes it
  (`POST /_merovingian/admin/accounts/{userId}`). The account is already closed for login, which is what matters.
* The check is repeated at each gate rather than made once at deactivation, because the failure it covers is exactly the
  one in which deactivation did not finish.
