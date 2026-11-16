# One function decides the legacy API switch, and each refused use answers as the spec says

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: plan P9, `server.oauth.legacy_api_enabled=false`, [OAuth 2.0 API plan](../todos/oauth-2-0-api.md),
[ADR-0813](0813-the-legacy-authentication-api-stays-on-by-default-and-a-config-key-turns-it-off.md)

## Context and Problem Statement

With `server.oauth.legacy_api_enabled=false` the legacy authentication API must stop listing logins and stop issuing
users new sessions, while application services keep `POST /register` and sessions already issued carry on. Seven
places issue or advertise a legacy session. Where is the decision made, and what does each refused use answer?

## Considered Options

* One pure function, `legacy_auth_refusal(OAuthConfig, LegacyAuthUse)`, that every affected route asks, answering
  the spec's status and errcode where the spec gives one and `404 M_UNRECOGNIZED` otherwise.
* A test of `legacy_api_enabled` in each route.
* `404 M_UNRECOGNIZED` for every refused use, application services included.

## Decision Outcome

Chosen option: the first. `homeserver::legacy_auth_refusal` (`LegacyAuthPolicy.cpp`) returns nothing while the key is
true, so with the default no answer changes. With it false:

| Use | Route | Answer | Spec |
|---|---|---|---|
| `login_flows` | `GET /login` | 404 `M_UNRECOGNIZED` | `GET /login` 404: "the homeserver does not support the legacy authentication API" |
| `user_login` | `POST /login`, any type but `m.login.application_service` | 404 `M_UNRECOGNIZED` | none of its own |
| `appservice_login` | `POST /login` `m.login.application_service` | 400 `M_APPSERVICE_LOGIN_UNSUPPORTED` | "it MUST return a 400 HTTP status code with an M_APPSERVICE_LOGIN_UNSUPPORTED error code" |
| `user_registration` | `POST /register` for a user | 403 `M_FORBIDDEN` | `POST /register` 403: "registration is generally not supported by the homeserver" |
| `appservice_registration_with_login` | `POST /register` `m.login.application_service` without `"inhibit_login": true` | 400 `M_APPSERVICE_LOGIN_UNSUPPORTED` | "the server MUST return a 400 HTTP status code with an M_APPSERVICE_LOGIN_UNSUPPORTED error code" |
| `sso_redirect` | `GET /login/sso/redirect`, `/{idpId}` | 404 `M_UNRECOGNIZED` | none of its own |
| `login_token_mint` | `POST /login/get_token`, the `m.get_login_token` capability | 404 `M_UNRECOGNIZED`, capability `enabled: false` | none of its own |

Rules the routes keep:

* The application-service checks of `POST /register` (a valid `as_token`, 401 otherwise) come first; the
  `inhibit_login` refusal follows, before the namespace checks and before the user is created, so a refusal stores
  nothing. With the legacy API on an application service without `inhibit_login` still gets a token.
* `POST /login` reads the body's `type` only once a login is refused, so with the key true the body is parsed once,
  as before.
* A user's `POST /register` is refused before User-Interactive Authentication, so no UIA session is issued.
* Not uses, and left alone: `/refresh`, `/logout`, `/logout/all`, every authenticated endpoint and UIA (P9: sessions
  already issued carry on), `GET /register/available`, the registration token validity check, the email and phone
  token requests and password reset by email, none of which issues a session. The in-process router's
  `/login` and `/register` (`LocalHttpRouter.cpp`) are not reachable from a client and are not gated.

### Positive Consequences

* One place to read what the switch does, and one unit-tested table.
* An application service gets the answer the spec names, which tells its operator what to change.

### Negative Consequences

* `POST /login` for a user, the SSO redirects and `get_token` answer as if absent, which a client cannot tell from an
  old server. The spec gives no other answer for them.

## Pros and Cons of the Options

### A test of `legacy_api_enabled` in each route

* Bad, because the seven places drift: a new route that issues a session would need its own copy.

### `404 M_UNRECOGNIZED` for every refused use

* Bad, because the spec requires 400 `M_APPSERVICE_LOGIN_UNSUPPORTED` for application services, and `POST /register`
  has a 403 for "registration is generally not supported".
