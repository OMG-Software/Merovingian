# Per-IP connection cap at accept time

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-27

Technical Story: 0.12.13 audit, remaining-work item 1 in
`docs/todos/audit-0.12.13-handover.md`. The default (64) and the exemption for
trusted proxies were chosen by the user in writing on 2026-09-27.

## Context and Problem Statement

Connection admission was bounded only by the global queue depth
(`listeners.max_queued_connections`) and the global parked keep-alive cap. One
host could open connections just under the slow-request thresholds, fill that
global budget and lock every other client out. The per-IP rate limiter could
not help: it runs only after a request has been parsed.

How should the number of connections one client may hold be bounded?

## Decision Drivers

* The bound must act before any per-connection work: no byte read, no TLS
  handshake.
* An IPv6 site is normally handed a whole /64, so a per-address count is
  trivially evaded.
* Behind a reverse proxy every client arrives from the proxy's address.
* No error path may leak a slot, or a client is locked out permanently.

## Considered Options

* **Cap at accept time, per client key (chosen).**
* Cap after the request is parsed, in the rate limiter. Rejected: by then a
  slow client has already held a worker for the head deadline, which is the
  attack.
* Count trusted proxies like any peer. Rejected by the user: one proxy would
  then share a single budget across all of its clients.
* A move-only slot. Rejected: the pool tasks that carry a connection between
  threads are copyable `std::function`s, so the slot is held through a shared
  pointer; exactly one task owns the connection at a time and the slot is
  released when the last copy goes.

## Decision Outcome

Chosen option: "Cap at accept time, per client key".

* `http::client_address_key` keys IPv4 as-is, IPv4-mapped IPv6 as the IPv4
  address it carries, and other IPv6 masked to
  `server.http.ipv6_client_prefix_length` (default 64). The per-IP rate
  limiter uses the same function (0.12.13 item 4).
* `http::ConnectionLimiter` counts open connections per key under a mutex and
  erases a key at zero, so memory is bounded by live connections.
* `serve_http` and `serve_tls_http`, which serve every listener, call
  `admit_connection` straight after `accept4`. Addresses in
  `server.trusted_proxies` are exempt; any other peer is refused once its key
  holds `server.http.max_connections_per_ip` (default 64) connections, and
  the socket is closed at once.
* The slot travels with the fd in `ConnectionContext` and in the sync-pool
  and keep-alive continuation tasks.

### Positive Consequences

* One host, or one IPv6 /64, can hold at most 64 connections by default.

### Negative Consequences

* Many users behind one NAT address share one budget; operators raise the cap.
* Behind a reverse proxy the per-client connection limit is the proxy's job.

## Links

* Tests: `tests/unit/test_http_connection_limiter.cpp`,
  `tests/integration/test_http_server_listener_flow.cpp` (`[connection_limit]`)
* `docs/http-transport.md`, "Per-client connection cap"
