# Method-not-allowed is decided by a static table before authentication, and by fall-through after it

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestUnknownEndpoints`)

## Context and Problem Statement

A known path called with a method it does not serve answered 404 `M_UNRECOGNIZED`. The spec's
`M_UNRECOGNIZED` says 404 if the endpoint is not implemented, 405 if it is implemented but the
wrong HTTP method is used. The client, media, key-server and federation surfaces all need it, and
the answer must not wait for authentication: a client probing an endpoint has no token yet.

## Considered Options

* A method table covering every route, templated paths included.
* A static table for fixed paths, answered before authentication, plus 405 after authentication
  for a templated path no handler took.

## Decision Outcome

Chosen option: the static table plus the fall-through, because a table of templated routes is easy
to get wrong and a wrong row refuses a real method.

* `client_static_route_allow` lists each fixed client and media path with every method it serves;
  `federation_methods_for_path` does the same for federation and key-server paths, before any
  signature check. A method not in the row is 405 `M_UNRECOGNIZED` with an `Allow` header.
* A row must list every method its path serves, or that method is refused. Add a method to the row
  in the same change that adds its handler.
* `OPTIONS` (CORS preflight) is answered before either check, on every path.
