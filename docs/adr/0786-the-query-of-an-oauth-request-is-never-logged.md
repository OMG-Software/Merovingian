# The query of an OAuth request is never logged

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5a of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

Every log line that names a request target goes through `observability::sanitized_http_target`, which keeps the query
and redacts the values of parameters whose names hold a marker such as `token`. The OAuth 2.0 pages and endpoints
carry secrets under names no marker list covers: `state`, `code`, `login_hint`, a pending authorisation identifier.
How are they kept out of the logs?

## Considered Options

* Drop the whole query of every target under `/_merovingian/oauth2` and `/_merovingian/account` in
  `sanitized_http_target`
* Add `state`, `code` and the others to the marker list
* Log nothing about OAuth requests

## Decision Outcome

Chosen option: drop the whole query of those paths, in `sanitized_http_target` itself.

The path `/_merovingian/oauth2` or `/_merovingian/account`, alone or followed by `/`, is logged without its `?` and
query. Every request-target log site in `ClientServerRuntime.cpp`, `HttpServer.cpp`, `LocalHttpRouter.cpp` and
`FederationProxy.cpp` already calls it, so none needs changing. Audit rows already drop every query
(`sanitized_audit_target`). `[observability][oauth]` in `tests/unit/test_observability.cpp` holds every path of
`oauth/OAuthPaths.hpp` to the rule, and `[oauth-log]` drives the dispatcher with the log captured at debug level.

### Positive Consequences

* A new OAuth parameter is safe in the logs without anyone remembering to list it.

### Negative Consequences

* An operator cannot see which parameters an OAuth request carried; the path, method and status remain.

## Pros and Cons of the Options

### More markers

* Bad, because `code` and `state` are common words in other queries, and the next OAuth parameter is missed.

## Links

* Same reasoning as [ADR-0418](0418-the-outbound-client-logs-an-url-without-its-query.md)
