# `auth_metadata` stays in the generic rate-limit tier

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 2 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), which put every OAuth route in the
`auth_sensitive` tier

## Context and Problem Statement

The plan put every new OAuth route in the `auth_sensitive` rate-limit tier (20 requests a minute per client). One of
them, `GET /_matrix/client/v1/auth_metadata` and its MSC2965 path, is read-only, unauthenticated, holds nothing
secret, and the spec marks it "Rate-limited: No". Element X reads it on every server probe, often from many devices
behind one address. Which tier does it take?

## Considered Options

* The generic tier, like the other unauthenticated discovery endpoints (`/versions`, `/login` flows).
* The `auth_sensitive` tier, as the plan said.
* No rate limit at all.

## Decision Outcome

Chosen option: the generic tier. `http::rate_limit_tier_for` has no entry for the two paths, so they fall to the
generic tier; the registration, token, revocation and device endpoints still take `auth_sensitive` when they land.

### Positive Consequences

* A household or office behind one NAT address cannot lock itself out of login discovery.
* The connection and request limits that protect every route still apply.

### Negative Consequences

* Unlike the spec's "No", requests are still counted; a client far above 600 a minute gets 429.
