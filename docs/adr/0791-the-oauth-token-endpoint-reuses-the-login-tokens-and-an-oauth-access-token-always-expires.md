# The OAuth token endpoint reuses the login's tokens, and an OAuth access token always expires

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 6 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md) (proposal P4)

## Context and Problem Statement

`POST /_merovingian/oauth2/token` turns an authorization code into a session. Which access and refresh tokens does it
issue, how long does the access token live, and what does the endpoint accept as a request?

## Decision Drivers

* The spec: "The access token MUST be short-lived" (Client-Server API, "Refresh token grant").
* `security.access_token_lifetime_ms` may be 0, which makes a legacy access token never expire.
* Every check a password login makes on a device (account state, the device cap, a device ID that is a cross-signing
  key ID) must hold for an OAuth session too.
* Every client of this server is public (`token_endpoint_auth_method` `none`, ADR-0779).

## Considered Options

* A separate token format and table for OAuth sessions, with their own lifetime setting.
* The existing opaque `mvs_` tokens, hashed and indexed as today, issued through the login's own checks, with the
  configured lifetime, or one hour when the configuration sets none.

## Decision Outcome

Chosen option: the second.

* `grant_oauth_session` (`AuthService.cpp`) runs `admit_device_login` and `mint_login_token`, the two halves
  `login_local_user_by_id` now uses, so the checks and the token are the login's; only the write differs (ADR-0792).
* The access token's lifetime is `oauth::access_token_lifetime_ms(security.access_token_lifetime_ms)`: the configured
  value when it is positive, otherwise `default_access_token_lifetime_ms` (one hour). `expires_in` is that lifetime in
  whole seconds, at least 1. A rotation through the refresh grant uses the same rule. The legacy API keeps its
  behaviour: 0 still means no expiry there.
* The token and revocation endpoints accept `application/x-www-form-urlencoded` with an optional `charset=utf-8`
  parameter, quoted or not (`api_form_content_type_is_accepted`); the authorisation pages keep the exact type
  (`page_form_content_type_is_accepted`), since only a browser posts to them.
* Client credentials are refused, never ignored: an `Authorization: Basic` header is 401 `invalid_client` with
  `WWW-Authenticate: Basic`, and a `client_secret` field is 400 `invalid_client` (RFC 6749 section 5.2). An unknown
  client is 400 `invalid_client`: no client authenticates, so a 401 would need a `WWW-Authenticate` challenge there is
  no scheme for.
* The refresh grant needs the client to be registered for `refresh_token`, else `unauthorized_client`, as the code grant
  needs `authorization_code`. Its `scope` parameter is ignored: the session keeps the scope it was granted.

### Negative Consequences

* An operator who set the lifetime to 0 for legacy clients gets one-hour OAuth access tokens and no setting to change
  that. It is the spec's MUST, not a choice to expose.
