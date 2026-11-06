# The health probe is answered by the connection handler, without a lock

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /_merovingian/admin/health` needs an admin token and is handled inside the dispatcher under `runtime.mutex`, so a
load balancer cannot use it and a probe would queue behind any request that holds the runtime lock. A probe needs an
unauthenticated answer that does not depend on how busy the server is.

## Decision Outcome

`GET /_merovingian/health` is answered in the connection handler (`http_server.cpp`), before `route_request`, on every
listener:

* `200` with the body `ok` while the dispatcher is running, `503` with `unavailable` once it has stopped
  (`HttpConnectionDispatcher::Impl::running()`, the flag a shutdown clears). The responses add
  `Content-Type: text/plain` and `Cache-Control: no-store` and nothing else.
* It reads that one atomic flag. It does not take `runtime.mutex`, the database, any room or session lock, or the rate
  limiter, so a request that holds the runtime lock for a long time cannot make a probe wait, and probes from a load
  balancer's one address are not throttled.
* It reveals nothing: no version, counts, configuration, server name or database state. It also says nothing about
  the database or the federation worker: it is a liveness and shutdown signal, not a dependency check. A probe that
  needs more uses the authenticated `/_merovingian/admin/health`.
* Only `GET` matches; the query string is ignored.

Rejected: serving it from the dispatcher like the admin routes (takes `runtime.mutex`, and the generic rate limit
would 429 a probe); reporting database or worker state (it would need a lock or a blocking call, and would leak
infrastructure state to anyone who can reach the port); a 200 body that varies with state.

### Negative Consequences

* A server whose database has failed but whose listener is up still answers `200`. Operators who want that signal use
  the admin route or their database monitoring.
* The probe still needs a free connection-pool worker to parse the request; per-address connection limits apply as to
  any connection.
