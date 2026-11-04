# Client routes are matched on the path without the query string

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`req.target` is the whole request target, query string included (the HTTP layer strips only `access_token`).
About thirty-five routes in `handle_client_server_request` compared it with `==`, so `POST /register?kind=user`
and an appservice's `GET /joined_rooms?user_id=@bot:example.org` matched no handler and an authenticated caller
got 405 from the end of the dispatcher. How should a route be matched?

## Considered Options

* Keep `req.target ==` and add a `starts_with(req.target, "<route>?")` alternative beside each.
* Strip the query once, in the HTTP layer, so `req.target` never holds one.
* Match every route on `request_path`, the target up to the first `?`, computed once at the top of the dispatcher.

## Decision Outcome

Chosen option: match on `request_path` (`target_path(req.target)` outside the dispatcher). The query is still in
`req.target` for the handlers that read parameters (`query_param_value(req.target, ...)`), for the audit target, and
for the rate-limit and route-known tables, which already normalise it.

The first option repeats the mistake in every new route and has already been forgotten once per route. The second
changes what handlers, the audit log and the signed-request checks see, and the media upload and `/search` handlers
read parameters from the target.

### Consequences

* A route that is only reachable with a query string no longer exists: a new route compares `request_path`, never
  `req.target ==`.
* An endpoint that takes no query parameter ignores one (the spec's API standards leave unknown parameters ignored).
* Routes that used to answer 405 for any query now reach their handlers. Appservice identity assertion
  (`?user_id=`) is still refused on Account Management by `is_account_management_endpoint`, which already judged
  `request_path`, before any handler runs.
