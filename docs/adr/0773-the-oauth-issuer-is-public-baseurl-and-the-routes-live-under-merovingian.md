# The OAuth issuer is `server.public_baseurl`, and the routes live under `/_merovingian/`

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: proposal P1 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The spec fixes only the discovery paths (`/_matrix/client/v1/auth_metadata` and its MSC2965 unstable path). The issuer
and every other OAuth address are whatever the metadata advertises. Where do they come from, and where do the
endpoints and pages live?

## Considered Options

* The issuer is `server.public_baseurl`; endpoints and pages live under `/_merovingian/oauth2/` and the account page at
  `/_merovingian/account`.
* A separately configured issuer and endpoint addresses.
* Endpoints at the root (`/authorize`, `/token`), as many standalone authorisation servers do.

## Decision Outcome

Chosen option: the first. `oauth::OAuthBaseUrl` reads `server.public_baseurl` (an `https` URL with a host and no
query; a path is allowed, and the scheme must be lowercase). `issuer()` is that URL with exactly one trailing slash,
and `url(path)` is that URL with its trailing slashes removed plus a constant from `oauth/OAuthPaths.hpp`. No other
code builds an OAuth address. With `server.oauth.enabled=true`, a `public_baseurl` the reader refuses fails
validation at start-up, naming both keys.

### Positive Consequences

* The metadata cannot name an address the server does not serve: one builder and one table of paths.
* A namespace this server owns cannot collide with `/_matrix/` or with a site the operator serves at `/`.
* A reverse proxy that already forwards `/_matrix/` needs one more prefix, `/_merovingian/`.

### Negative Consequences

* An operator who hosts Merovingian under a path must forward `/<path>/_merovingian/` too.
* Moving a route later changes an address clients may have cached; the paths are fixed in one header so a change is
  deliberate.

## Links

* Refines [ADR-0816](0816-server-oauth-replaces-server-oidc-and-the-old-keys-are-refused.md)
