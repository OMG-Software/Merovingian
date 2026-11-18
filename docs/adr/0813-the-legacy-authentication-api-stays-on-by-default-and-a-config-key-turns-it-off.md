# The legacy authentication API stays on by default, and a config key turns it off

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

The spec lets a homeserver offer the legacy authentication API, the OAuth 2.0 API, or both. Once Merovingian offers
the OAuth 2.0 API ([ADR-0812](0812-the-oauth-2-0-api-is-built-into-the-homeserver.md)), what happens to
`POST /login` and `POST /register`?

## Decision Drivers

* Most clients other than Element X still log in through the legacy API.
* An operator who wants every login to pass through the server's own pages should be able to have that.
* Enabling a feature must not sign existing users out.

## Considered Options

* Both APIs on, always.
* Both on by default, with a key that turns the legacy API off.
* The legacy API off whenever the OAuth 2.0 API is on.

## Decision Outcome

Chosen option: "Both on by default, with a key that turns the legacy API off". `server.oauth.legacy_api_enabled`
defaults to `true`. With `false`, the legacy endpoints stop issuing sessions to users, and the server answers as the
spec says a server without the legacy API answers: `GET /login` is `404 M_UNRECOGNIZED`, and `POST /register` serves
only application services, which must set `inhibit_login`. The key is refused at start-up unless
`server.oauth.enabled` is `true`, so a configuration can never leave users with no way to log in.

### Positive Consequences

* Turning the OAuth 2.0 API on changes nothing for a client that does not use it.

### Negative Consequences

* With both on, the server has two ways to obtain a session, and every rule about sessions has to hold for both.
  A check added to one login path must be added to the other.

## Pros and Cons of the Options

### Both APIs on, always

* Bad, because an operator cannot require that passwords are typed only into the server's own pages.

### The legacy API off whenever the OAuth 2.0 API is on

* Good, because there is one login path.
* Bad, because enabling the feature would lock out every client that has not adopted the OAuth 2.0 API.
