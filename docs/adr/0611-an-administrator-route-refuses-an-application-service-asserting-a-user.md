# An administrator route refuses an application service asserting a user

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `F-authz.appservice-masquerade.admin-routes-accept-asserted-admin`.

## Context and Problem Statement

An application service may act as any user inside its `users` namespace. A namespace that covers a server administrator
gave the service every operator route and client admin route, because `require_admin` and `authenticated_admin_user`
asked only whether the resolved user was an administrator. Possession of an `as_token` is not the administrator's
credential.

Where is the line drawn?

## Decision Drivers

* An `as_token` is a credential for the service's own users, read from a registration file and shared with a third-party
  process.
* Every administrator check goes through the two functions in `AuthService.cpp`.
* An operator can register a namespace wider than they meant to.

## Considered Options

* Refuse only when the asserted user is an administrator.
* Refuse every masquerade token at the two functions, whatever user it asserts.
* Refuse administrator users at registration load, in the namespace check.

## Decision Outcome

Chosen option: "Refuse every masquerade token at the two functions, whatever user it asserts".

* `require_admin` keeps its `401` for a token that does not authenticate and answers `403` (`not_admin`) for a masquerade
  token. `authenticated_admin_user` returns no user, so the client admin routes and the `m.account_moderation` capability
  treat the caller as an ordinary user.
* A check at registration load would be out of date as soon as a user in the namespace was promoted.
* An application service asserting a user keeps every ordinary route.

### Positive Consequences

* Administrator authority can be exercised only with an administrator's own session.

### Negative Consequences

* A bridge cannot call an admin route for a user it controls, even if that user is an administrator. It has to log in
  as that user.
* `check_local_redaction` judges its server-administrator override by user ID, below the layer that has the token, so an
  application service asserting an administrator keeps that override for a local user's event. It is not an administrator
  route; the service could already send as that user.
