# An OAuth approval is judged again and audited, and its redirect sends no referrer

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5b of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

`approve` on the consent page turns a signed-in user into an authorization code. Between the password and the
approval the account can be deactivated or locked, and the approval itself is the moment the user hands a device to
an application. What does `approve` check, what does it record, and what does the redirect to the client carry?

## Decision Drivers

* The password check releases `runtime.mutex`; the consent page can be left open for minutes.
* `auth.login` is a durable audit row; an approval grants the same access through another door.
* The authorisation request's address is not the client's business once the browser leaves this server.

## Considered Options

* Trust the user recorded at sign-in, log only, and let the browser's referrer policy apply.
* Judge the account again at `approve`, audit the grant, and send `Referrer-Policy: no-referrer` on the redirect.

## Decision Outcome

Chosen option: the second.

* `approve` consumes the pending authorisation, then asks `account_sign_in_gate` again, the gate
  `verify_password_login` uses. An account that may no longer sign in gets `access_denied` at the client, never a
  code. The gate is the same function, so the two cannot disagree.
* `oauth.authorization.granted` is a durable audit row (category `auth`, actor the user, target the client ID, reason
  the device ID), as `auth.login` is. `oauth.authorization.denied` is audited the same way only when a user had signed
  in: a denial before the password can be sent by anyone and would let a stranger fill the audit log. Refusals of the
  request are diagnostic log lines only, bounded by the `auth_sensitive` rate limit.
* Every redirect to the client carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. A redirect is
  not a page, so it does not carry the pages' headers (`same-origin`, ADR-0784); `no-referrer` is stricter and keeps
  this server's address out of the client's page.

### Positive Consequences

* A deactivation between sign-in and approval issues no code.
* Every grant can be found in the audit log, as every password login can.

### Negative Consequences

* One more audit row per sign-in through the pages.

## Links

* Builds on [ADR-0783](0783-login-verification-and-account-creation-are-one-function-each-shared-by-the-matrix-routes-and-the-oauth-pages.md)
  and [ADR-0784](0784-oauth-pages-use-a-same-origin-referrer-policy-and-a-form-post-must-name-this-server-s-origin.md)
