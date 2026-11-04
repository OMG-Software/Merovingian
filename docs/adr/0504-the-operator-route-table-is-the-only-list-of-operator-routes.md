# The operator route table is the only list of operator routes

* Status: accepted
* Date: 2026-11-04

Technical Story: project analysis item G5

## Context and Problem Statement

`observability::admin_routes()` declared `/_merovingian/admin/accounts/{userId}`, `.../review/...` and `.../shutdown`,
and `match_admin_route` matched them, but nothing in the dispatcher called it. The dispatcher compared path strings in
`local_http_router.cpp`, and the rate limiter kept a second list in `normalized_target`. The declared routes were
never served, `docs/todos/capability-gaps.md` marked them `not-started`, and nothing noticed, because a table that
nothing reads cannot fail. How do the declared list and the served list stay one list?

## Decision Drivers

* A route that is declared must be served, and a route that is served must be declared.
* The rate limiter must file a request under a fixed key, so a client cannot create counter keys by inventing paths
  (F-73, ADR-0092).
* An operator route is a security surface: its path must not match more than it declares.

## Considered Options

* Delete the table and keep the string comparisons.
* Keep the table as documentation and test that the two agree.
* Make the table the list the dispatcher, the local router and the rate limiter read.

## Decision Outcome

Chosen option: "make the table the list everything reads". `admin_routes()` declares every route under
`/_merovingian/admin/` (including the media moderation and `media/metrics` routes that were never in it).
`match_admin_route(method, path)` is strict: a `{name}` matches exactly one non-empty segment, so an extra, empty or
missing segment matches nothing (the old matcher took any child of `/accounts/`).

* `handle_client_server_request` answers `404 route not found` for a path or method the table does not declare, and
  passes the rest to the local router.
* The local router asks the table for the operation (`AdminOperation`) and never compares a path.
* `normalized_target` uses `match_admin_path(path).route.path_template` as the counter key (`.../accounts/{userId}`),
  and the fallback key for anything else. The two lists in `normalized_target` (`operator_routes`, `media_actions`) are gone.
* A test walks `admin_routes()`, calls each route as an administrator, and asserts none is answered as a route that
  does not exist; another asserts that two identifiers share one counter.

A route is added by adding a row to `admin_routes()` and an `AdminOperation`, then handling the operation in the local
router. Without the handler the walk test fails; without the row the route is a 404.

### Negative Consequences

* A request with a known path and a wrong method is a 404, as it was, not a 405.
* The table is read on every request to `/_merovingian/admin/`. It is ten rows and a segment compare, with no allocation.

## Links

* Related: [ADR-0505](0505-the-server-cannot-be-stopped-over-http.md), [ADR-0506](0506-deactivation-by-an-administrator-needs-an-explicit-confirm.md)

## Status format of the operator surface

The operator surface answers an error with a status and a plain-text line (`admin authentication required`, `route
not found`, the media routes), never a Matrix `errcode` object, and a result with JSON (`/audit`, and now the accounts
and review routes). The new routes keep that: they are not Matrix endpoints and no client library reads them. The
review route's shared implementation returns a status and a message; the client route renders them as Matrix errors and
the operator route as text. Oversized account bodies are `413`; every other malformed body is `400`.

## Changed answers

A media moderation path with an extra segment (`/media/remove/../id`) or an empty identifier (`/media/release/`) is now
`404`, not `400 invalid media id`: it matches no row. `tests/integration/test_media_repository_security.cpp` was updated
to say so; the media item is untouched either way.
