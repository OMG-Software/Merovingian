# Deactivation by an administrator needs an explicit confirm

* Status: accepted
* Date: 2026-11-04

Technical Story: project analysis item G5

## Context and Problem Statement

`POST /_merovingian/admin/accounts/{userId}` takes `{"action": "..."}` with `deactivate`, `lock`, `unlock`, `suspend` or
`unsuspend`. Four are reversible. Deactivation is not: tokens, pushers and the password hash are destroyed, and the
localpart is never reissued. Should `{"action":"deactivate"}` alone deactivate?

## Decision Drivers

* An operator who meant `lock` and typed `deactivate`, or a script that builds the action from a variable, must not
  destroy an account by accident.
* The owner's own deactivation already needs a deliberate step (UIA with the password).

## Considered Options

* `{"action":"deactivate"}` deactivates.
* Deactivation needs `"confirm": true` in the body.
* Deactivation needs a second request, a confirmation token.

## Decision Outcome

Chosen option: "`\"confirm\": true`". A `deactivate` without it, or with `false` or a non-boolean, is `400` and changes
nothing. The check needs no server state (a confirmation token would be state to expire and secure) and is harder to
meet by accident than a bare action name.

The same deactivation runs for the owner and for an administrator (`deactivate_user_account`), so the effects (tokens,
refresh and OpenID tokens, pushers, password hash) are one set. A repeat on a deactivated account runs every step again
and answers `200`, which completes a deactivation that failed part way. The other four actions on a deactivated account
are `409`.

An administrator's deactivation does not unbind the account's identity-server 3PIDs: that is a blocking network call per
address, which an operator route does not make under `runtime.mutex`. The owner's deactivation does.

## Links

* Related: [ADR-0504](0504-the-operator-route-table-is-the-only-list-of-operator-routes.md)
