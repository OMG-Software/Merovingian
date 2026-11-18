# OAuth and legacy sessions do not mix at the refresh endpoints

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 6 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

Both APIs issue the same kind of refresh token. Should `POST /_merovingian/oauth2/token` with
`grant_type=refresh_token` rotate a legacy session, and should the legacy `POST /refresh` rotate an OAuth one?

## Considered Options

* Accept any refresh token at either endpoint.
* Accept at each endpoint only the sessions it issued, decided before anything is rotated.

## Decision Outcome

Chosen option: the second.

* `refresh_local_session` takes an optional client ID. With one (the token endpoint), the token's device must hold an
  `oauth_sessions` row naming that client; without one (`POST /refresh`), the device must hold none. A mismatch is
  refused as an unknown token (401 inside; `invalid_grant` or `M_UNKNOWN_TOKEN` outside) before the reuse check and
  before any rotation, so it changes nothing, not even the reuse bookkeeping of ADR-0590.
* The token endpoint turns every 4xx of `refresh_local_session` into 400 `invalid_grant` and a 5xx into 500
  `server_error`, so a client follows the spec's rule: 4xx means logged out, 5xx means retry.
* An OAuth rotation's access token takes the OAuth lifetime (ADR-0791).

### Positive Consequences

* A leaked legacy refresh token cannot be turned into an OAuth session by naming any registered client, and an OAuth
  session cannot be refreshed through the legacy endpoint, which knows nothing of clients.
