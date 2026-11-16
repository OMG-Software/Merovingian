# The registration page applies the legacy registration settings

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

Under the OAuth 2.0 API an account is created on a page the homeserver serves, and the spec gives the homeserver
"complete control over the requirements to create a new account". `POST /register` is governed by
`security.registration.enabled`, `require_token`, `allow_open_registration` and `token_file`. What governs the page?

## Considered Options

* The page applies `security.registration.*`, and nothing else.
* The page has settings of its own.
* The page always requires a registration token.
* The page also requires a verified email address.

## Decision Outcome

Chosen option: "The page applies `security.registration.*`, and nothing else". The page calls the function
`POST /register` calls, so the enabled flag, the registration token, the username rules, the reserved localparts,
the password rules, the registration policy rule and the Argon2id admission budget all apply. The page offers
account creation, and the metadata lists `create` in `prompt_values_supported`, only while
`security.registration.enabled` is `true`.

### Positive Consequences

* An operator reasons about one registration policy. A server that is closed to registration is closed on both
  paths, and a registration token cannot be bypassed by choosing the other path.

### Negative Consequences

* An operator cannot open registration for Element X while keeping it closed for legacy clients, or the reverse.
  [ADR-0813](0813-the-legacy-authentication-api-stays-on-by-default-and-a-config-key-turns-it-off.md) gives the
  nearest equivalent: turn the legacy API off.

## Pros and Cons of the Options

### The page has settings of its own

* Bad, because two policies for one act is how one of them ends up open by mistake.

### The page also requires a verified email address

* Good, because it raises the cost of mass registration.
* Bad, because it needs SMTP configured and adds a verification flow to the page. It can be added later without
  changing this decision.
