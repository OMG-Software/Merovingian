# The access_token query parameter is read on client-server and media routes only, and the header wins

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

Matrix v1.19 ("Using access tokens") says clients may send the access token as
the `access_token` query parameter and that "Homeservers MUST support both
methods". The server read only `Authorization: Bearer`, so a request with
`?access_token=` was treated as having no token (`M_MISSING_TOKEN`).
Complement's blueprint runner sends every token that way, so every blueprint
with a user that sets a display name (`hs_with_application_service`,
`alice`, ...) failed to build. Run 12 showed it as `[terminated]`, the runner's
message for "another instruction set already failed".

Where is the query parameter read, and what wins when both forms are sent?

## Considered Options

* Read it in `build_local_request` (`http_server.cpp`), for targets under
  `/_matrix/client/` and `/_matrix/media/` only, and only when there is no
  `Authorization` header.
* Read it for every target.
* Refuse a request that carries both forms.
* Read it deep in `client_server.cpp`, after routing.

## Decision Outcome

Chosen option: the first. `build_local_request` is the one place a transport
request becomes a `LocalHttpRequest`, and it also builds the head-only request
that `media_upload_authentication_refusal` judges before a large upload body is
read (ADR-0077), so a query token is honoured before the body as well.

* Federation routes authenticate with X-Matrix. The one federation route that
  takes a query `access_token`, OpenID `userinfo`, reads its own parameter from
  the target; giving every federation request a `LocalHttpRequest::access_token`
  would hand a client credential to code that must never look at one.
* The spec is silent about a request with both forms. The header wins, the
  query value is ignored, and nothing is rejected: the deprecated form is the
  fallback, never an override. This is a choice, not a spec requirement.
* The token is percent-decoded. The logged target already redacts the value
  (`observability::sanitized_http_target`), so accepting the query form leaks
  nothing new into logs.

### Negative Consequences

* A token in a URL can end up in a reverse proxy's access log. The spec
  deprecates the form for that reason; the server supports it because it MUST.

## Links

* Spec: `docs/matrix-v1.19-spec/client-server-api.md`, "Using access tokens"
* Related: ADR-0077 (authenticate a media upload head before reading its body)
