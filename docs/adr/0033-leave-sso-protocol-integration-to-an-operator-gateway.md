# Leave SSO protocol integration to an operator gateway

* Status: accepted
* Date: 2026-09-06

Amended 2026-11-16: `server.sso.authorization_url` cannot be combined with `server.oauth.enabled`, and a configuration
that sets both is refused at start-up. With OAuth on, the legacy SSO redirect hands off to the built-in OAuth 2.0 pages
instead of an operator gateway
([ADR-0802](0802-the-legacy-sso-redirect-hands-off-to-the-built-in-pages-confirms-and-mints-a-30-second-login-token.md)).

## Context and Problem Statement

Matrix SSO login requires the homeserver to hand off to an external system —
CAS, SAML, OIDC — and resume once that system has authenticated the user. Each
of those is a substantial protocol with its own security pitfalls.

## Considered Options

* Implement every homeserver-side piece of the flow, and leave the external
  protocol to the operator's own SSO gateway
* Implement CAS/SAML/OIDC directly in Merovingian

## Decision Outcome

Chosen option: "Implement the homeserver-side pieces only". Merovingian
provides the redirect endpoints, the `redirectUrl` allowlist, login-token
minting and redemption, and `homeserver::complete_sso_login` as the integration
point an adapter calls.

Identity mapping and just-in-time registration are the adapter's
responsibility, because they are inherently specific to the external protocol
in use.

### Positive Consequences

* Merovingian never parses SAML assertions or OIDC tokens — a large, historically
  vulnerable attack surface that stays out of the process entirely.

### Negative Consequences

* Merovingian is not drop-in for an operator who expects built-in OIDC; they
  must run an adapter.
* `complete_sso_login` re-validates `redirectUrl` against the allowlist rather
  than trusting the adapter, because a value handed across an integration
  boundary must never be trusted a second time without re-checking.

## Links

* [`docs/auth-identity.md`](../auth-identity.md), "SSO login"

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
