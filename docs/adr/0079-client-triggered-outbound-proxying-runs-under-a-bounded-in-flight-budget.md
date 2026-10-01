# Client-triggered outbound proxying runs under a bounded in-flight budget, not a separate pool

* Status: accepted
* Date: 2026-09-30

Technical Story: 2026-09-29 security audit, findings HTTP-2 (unauthenticated
directory endpoints pin workers on blocking outbound federation calls) and OUT-7
(`security.media.remote_fetch_enabled=false` does not stop remote media
fetches) in `docs/security-audit-report-2026-09-29.md`.

## Context and Problem Statement

Some client requests make this server call another one before they can answer:
`GET`/`POST /publicRooms?server=`, `GET /directory/room/{alias}` for a remote
alias, and a download or thumbnail of remote media. The Matrix spec allows all
of them without authentication. Each one ran server discovery and then a
federation request synchronously on the request thread, with a 60 s
`remote_timeout` (media: 120 s per request and up to about 150 s in all).
`RuntimeLockRelease` frees the runtime mutex during the wait, not the thread.

The main request pool is 8 threads. One attacker-controlled peer that accepts a
connection and never answers therefore pins all 8 with roughly 8 requests a
minute, which stalls every client and every inbound federation request. The
same calls also make this server send signed requests to a destination and on a
schedule the attacker picks.

How should client-triggered outbound calls be bounded, given that the caller
cannot be authenticated first and the pool is small?

## Decision Drivers

* The bound has to hold for a caller we cannot identify beyond its address.
* Half the request pool must stay available to requests that never leave this
  server, whatever the peer does.
* A refused request must cost nothing: no queueing, no waiting, no held thread.
* The pool size is about to become configurable (finding HTTP-1), so the caps
  must follow it rather than restate the number 8.
* No error path may leak a slot, or a client is locked out for good.

## Considered Options

* **A small in-flight budget with a short deadline, taken on the request thread
  (chosen).** Over the cap the request is refused with 429 `M_LIMIT_EXCEEDED`
  at once.
* A separate thread pool for proxied calls, or an asynchronous rewrite of the
  proxy path. Rejected for now: it moves the blocked thread instead of
  removing it, it needs its own queue bound and its own shedding rule (which is
  this same budget again), and it hands responses back across threads that the
  request path, the runtime lock and the CORS/response helpers do not expect.
  It is the right long-term shape if these paths ever need to scale past a
  handful of concurrent calls; nothing here makes it harder.
* Require authentication for remote proxying. Rejected: the spec permits
  unauthenticated access to these endpoints, and an account is cheap where
  registration is open.
* Queue over-cap requests. Rejected: a queue turns an overload into a slower
  overload while holding the same resources.

## Decision Outcome

Chosen option: "A small in-flight budget with a short deadline".

* `http::InFlightBudget` is the admission guard: thread-safe, RAII `Slot`,
  global cap plus per-key cap, never waits. `HomeserverRuntime` owns one
  (`client_outbound_budget`) and a `ClientOutboundProxyPolicy`
  (`client_outbound_proxy_policy`).
* Every client-triggered outbound call takes a slot before it releases the
  runtime lock and keeps it until the call has ended: `publicRooms` with
  `server=` (GET and POST), the remote alias lookup, and the remote media
  download and thumbnail fetch. Authenticated callers go through it too: the
  cap protects the pool, whoever calls.
* Global cap: half the main request pool (4 of 8), derived from the single
  named constant `main_request_pool_threads` in
  `homeserver/client_outbound_proxy.hpp`. HTTP-1 replaces that constant with
  the configured pool size and the caps follow.
* Per-client cap: 1 in flight per client key, the same key the rate limiter
  uses (`rate_limit_client_key`: `trusted_proxies` honoured, IPv6 grouped by
  prefix).
* Over either cap: 429 `M_LIMIT_EXCEEDED` with `retry_after_ms` 1000 and a
  `Retry-After` header, without waiting and before any discovery or outbound
  call.
* Total deadline, discovery included: 10 s for directory lookups, 30 s for
  remote media, never longer than the operator's `remote_timeout` when that is
  set. Discovery and the requests that follow draw from one
  `OutboundDeadline`. The federation-worker round trip for a bounded call may
  exceed the deadline by at most 2 s (`worker_margin_seconds`), not the usual
  10 s.
* The constants are code, not configuration. A config key would let an
  operator raise them back above the pool size, which is the bug.
* OUT-7: `security.media.remote_fetch_enabled` and the `allow_remote` query
  parameter are checked at the top of every remote media route, before any
  discovery. A disabled or refused remote fetch is 404 `M_NOT_FOUND`.

### Positive Consequences

* One attacker-controlled peer can hold at most 4 threads, and one address at
  most 1, for at most 10 s (30 s for media) at a time.
* No new thread pool, queue or lifecycle.

### Negative Consequences

* A legitimate burst of remote lookups from one client is refused with 429
  instead of served, and a busy server refuses lookups from unrelated clients
  while 4 are in flight. That is the intended trade.
* Clients behind one address that is not a configured trusted proxy share one
  slot.
* A DNS resolver stall inside discovery is bounded by the resolver, not by this
  deadline (discovery only takes the deadline as its well-known timeout).
* Threads are still held while a call is in flight. The budget bounds how many;
  the pool-size work (HTTP-1) and, if it becomes necessary, an asynchronous
  proxy path address the rest.

## Links

* Related to [0072 - Per-IP connection cap at accept time](0072-per-ip-connection-cap-at-accept-time.md)
* Related to [0073 - The client address is the rightmost untrusted X-Forwarded-For entry](0073-client-address-is-the-rightmost-untrusted-x-forwarded-for-entry.md)
* Related to [0080 - Rate-cap audit rows for unauthenticated rejections](0080-rate-cap-audit-rows-for-unauthenticated-rejections.md)
