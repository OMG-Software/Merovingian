# Unknown client-server endpoints answer 404 M_UNRECOGNIZED before authentication

* Status: accepted
* Date: 2026-10-26

Refines [ADR-0092](0092-normalize-rate-limit-routes-and-evict-lru.md).

## Context and Problem Statement

The client-server dispatcher checks the access token before it looks for a
matching route, and only reaches its `404 M_UNRECOGNIZED` fallback once the
request is authenticated. A request for an endpoint the server does not
implement was therefore answered `401 M_MISSING_TOKEN` (no token) or
`401 M_UNKNOWN_TOKEN` (a bad one). Element X, while logging in, asked for
`GET /_matrix/client/r0/login`, a path v1.19 does not define, and was told it
needed an access token it cannot have before logging in. Each probe also wrote
an `access_token.rejected` warning.

v1.19 describes `M_UNRECOGNIZED` as "expected to be returned with a 404 HTTP
status code if the endpoint is not implemented", and its Authentication API
discovery section says a server SHOULD answer `404 M_UNRECOGNIZED` to a login
API it does not support. Neither makes the answer depend on credentials. How
does the dispatcher know a path names no endpoint before it authenticates?

## Considered Options

* Use `normalized_target()`, the rate-limit route matcher, as the list of
  served paths, and answer a path it cannot place with `404` before
  authenticating.
* Refuse only unsupported API versions (`r0`, `api/v1`, …) before
  authenticating, and leave every other unknown path behind the token check.
* Defer the `401` into each route branch, so authentication runs only once a
  route has matched.
* Keep authenticating first, and only change the audit reason.

## Decision Outcome

Chosen option: `normalized_target()` decides whether a path names a served
endpoint. ADR-0092 already required every implemented route with a variable
path component to have a template there, so the matcher already almost
listed every served path. A route-security audit found five that it did not
place (the three `thirdparty/{kind}/{protocol}` lookups, `GET
/pushrules/global/` and the body-typed `POST /rooms/{roomId}/send`); they are
recognised now. The dispatcher calls `client_route_is_known()` immediately
before the access-token check and answers an unplaced path
`404 M_UNRECOGNIZED`, with or without credentials.

The check is on the path, not the method. A served path asked for with a method
it does not serve still authenticates first and reaches the existing fallback,
so it gets `401` or `404` as before (the spec's `405` for that case is a
separate gap).

Refusing only unsupported version prefixes answers the Element X probe but
leaves `/_matrix/client/v3/no_such_endpoint` at `401`, which is the same
defect. Deferring the `401` into each branch would make the dispatcher answer
correctly by construction, but means editing every one of its route branches
(roughly 160) and checking each by hand. Changing only the audit reason leaves
the client misled.

### Positive Consequences

* A client probing an endpoint this server does not serve learns that at once,
  whatever its credentials, as the spec asks.
* Unknown paths no longer reach the token check, so they write no
  `access_token.rejected` audit row.
* One matcher answers two questions, rate-limit key and route existence, so a
  new route is registered once.

### Negative Consequences

* A route served by the dispatcher but missing from `normalized_target()` is
  now answered `404` for every caller, not only rate-limited in the shared
  fallback bucket. Adding a route therefore needs a template, or for a fixed
  path an entry in `static_routes`, in the same change; the
  `[unknown-endpoint]` conformance scenarios and the existing route tests are
  what catch an omission.
* A caller without credentials can now tell a served path (`401`) from an
  unserved one (`404`). This discloses nothing that is not already public: the
  server's source is published, `/versions` advertises what it supports, and
  the spec asks for exactly this answer.
