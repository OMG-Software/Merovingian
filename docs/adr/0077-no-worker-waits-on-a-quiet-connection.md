# No worker waits on a quiet connection: a dispatcher thread holds idle connections, with a per-client worker share

* Status: accepted; amends [ADR-0072](0072-per-ip-connection-cap-at-accept-time.md) (the per-IP connection cap no longer stands for a bound on one client's worker threads, and its slot is no longer carried by a shared pointer)
* Deciders: James Chapman
* Date: 2026-09-30

Technical Story: 2026-09-29 security audit, findings HTTP-1 (one client can hold
every worker in the main request pool) and HTTP-8 (keep-alive connections have
no request-count or lifetime limit), with the transport half of HTTP-6.

## Context and Problem Statement

The main request pool was a hard-coded 8 threads, and a worker stayed tied to
its connection from the moment it was accepted: while it waited for the first
byte (5 s), for the next keep-alive request (the 15 s idle window), for a
dribbled head (30 s) or ClientHello (15 s), and for a body under a 5 s
inter-byte gap and a `30 s + length / 16 KiB` deadline. The parked-connection
cap (8) equalled the pool, and the per-IP connection cap (64, ADR-0072) was
eight times it. So eight sockets from one address stalled every client and
every inbound federation request, on every listener, at a cost of about 0.6
requests per second, all of it protocol-conformant. Media uploads raised the
body cap to 50 MiB before authentication, so one byte every 4.9 s held a
worker for about 54 minutes.

How should the transport stop one client from holding the workers everyone
else needs, without a rewrite of request handling?

## Decision Drivers

* A worker must only ever be given a connection that has something to read.
* One client (one address, IPv6 grouped by prefix) must not be able to take
  more than a fraction of the workers, whatever it does, and legal behaviour
  (keep-alive, slow uploads) must keep working.
* Request handlers are synchronous and hold the runtime lock; they cannot be
  made asynchronous in this change.
* Linux and the BSDs, no new dependency; no thread before hardening
  (ADR-0082); shutdown bounded.

## Considered Options

* **A single dispatcher thread holding every waiting connection in one
  `poll(2)` set, dispatching readable ones under a global and a per-client
  cap (chosen).**
* Keep workers tied to connections, but make the pool larger and lower the
  per-IP connection cap below the pool. Rejected: every fixed ratio is beaten
  by a few more addresses, and a big pool of mostly idle threads costs memory
  and still parks threads on quiet sockets.
* A full reactor that also reads request heads (and bodies) without a worker,
  dispatching only complete requests. Rejected for now: it moves all parsing
  and TLS record handling onto an event loop, a far larger change. A readable
  connection's head is still read on a worker, but the head deadline (30 s) is
  then bounded by the per-client share.
* `epoll`/`kqueue`. Rejected for now: `poll(2)` is portable across every
  supported platform, and the set is bounded by the parked-connection caps;
  switching is local to `net::ConnectionParker` if it ever matters.
* Exempting nobody from the per-client share. Rejected: behind a reverse proxy
  every client arrives from one address, which would get a quarter of the pool
  for all of its users.

## Decision Outcome

Chosen option: the dispatcher. The rules below are the decision; each is
something a future change could undo by accident.

1. **No worker waits on a quiet connection.** `net::ConnectionParker` (one
   thread, started in `start()`, after hardening) owns every connection that
   is not being served: a new one before its first byte, a TLS one before its
   ClientHello and again after the handshake, a kept-alive one between
   requests. It hands a connection to the pool only once it is readable, or
   holds input above the socket (pipelined bytes; TLS records OpenSSL already
   read, `TlsConnection::has_pending_input`). It enforces the first-byte
   (5 s) and idle (`keep_alive_idle_seconds`) timeouts itself. A worker that
   has written a kept-alive response hands the connection back; it never
   waits for the next request.
2. **Per-client worker share.** At most `max(1, pool / 4)` connections from one
   client key are held by workers at once; at most `pool` in total, so the
   pool's queue never exceeds its workers. The key is `client_address_key` of
   the TCP peer (the ADR-0072 key). A readable connection over its client's
   share waits in the dispatcher, outside the poll set, and is dispatched oldest
   first when one of that client's shares is released. A connection handed to
   the sync pool releases its share. Connections from `server.trusted_proxies`
   are exempt from the share (the proxy must enforce per-client fairness) but
   not from the global bound.
3. **Minimum body rate.** After a 10 s grace from the start of the body read,
   the bytes received so far must be at least 16 KiB/s × (elapsed − 10 s),
   checked continuously; otherwise 408 and close. It replaces the whole-body
   deadline and the 5 s body inter-byte gap. The size caps are kept.
4. **Authenticate before reading a large upload.** A media upload over the
   1 MiB transport cap is read under `max_upload_size` only when its head's
   access token authenticates (`media_upload_authentication_refusal`: a live
   session or an appservice `as_token`, under the runtime lock, before any body
   byte). Otherwise the response is the dispatcher's own 401
   `M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN` (spec: Client authentication), and the
   connection is closed since its body is unread.
5. **Per-connection caps (HTTP-8).** `Connection: close` on the response to a
   connection's 1 000th request, or on any response once it is an hour old.
6. **Configurable pool.** `server.http.request_threads`, 4..256, default 16,
   restart required. The ADR-0079 outbound caps are computed from it
   (`client_outbound_proxy_policy_for_pool`), so they stay at half the pool.
7. **Ownership and locking.** A connection is a `std::unique_ptr<HttpConnection>`
   owned by exactly one of the dispatcher, one pool task or one sync-pool task,
   and destroying it releases everything it holds. (Pool tasks are copyable
   `std::function`s, so the unique pointer rides in a shared holder that
   exactly one task consumes.) The parker's mutex is a leaf: it is never held
   while polling, closing a connection or calling the dispatch callback, so
   the callback may re-park and release shares freely. The parking budgets are
   atomics. The dispatcher's internals are shared with the pool tasks, so a
   worker can always hand its connection back, and after `request_stop()` a
   handed-back connection is closed. Shutdown: stop accepting, stop the
   dispatcher (closes every parked connection at once), then drain the pools.
8. **TLS handshake stays on a worker**, started only once the ClientHello is
   readable, bounded by the 15 s handshake timeout and by the per-client share.

### Positive Consequences

* Idle, not-yet-readable and kept-alive connections cost no worker; one client
  can hold at most a quarter of the pool, for at most the head deadline or at
  the minimum body rate.
* `keep_alive_max_connections` no longer has to relate to the pool size; it
  bounds descriptors and memory. `listeners.max_queued_connections` now bounds
  connections waiting for their first request.
* A TLS input already buffered by OpenSSL is no longer invisible to the
  transport's waits.

### Negative Consequences

* A client may use only a quarter of the pool at once, so a user with many
  devices behind one NAT address, or a busy federation peer, may see its own
  requests queue behind each other. Operators raise `request_threads`.
* Behind a reverse proxy the proxy must limit concurrent requests per client.
* Many distinct addresses can still share out the pool; the share bounds one
  address.
* The dispatcher rebuilds its `poll` set on every wake-up, O(parked); fine at
  the configured caps, and the reason to move to `epoll`/`kqueue` if the caps
  are raised by orders of magnitude.

## Links

* Amends [ADR-0072](0072-per-ip-connection-cap-at-accept-time.md): the per-IP
  connection cap remains and still decides admission at accept time; the
  claim that it bounds one host's share of the server's workers was wrong and
  is replaced by rule 2 above.
* Relates to [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
  (caps derived from the pool size), [ADR-0082](0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)
  (thread start order), [ADR-0054](0054-tls-sockets-stay-non-blocking-for-the-life-of-the-connection.md)
  (non-blocking sockets), [ADR-0073](0073-client-address-is-the-rightmost-untrusted-x-forwarded-for-entry.md)
  (trusted proxies).
* Tests: `tests/integration/test_http_worker_fairness_flow.cpp` (`[http-1]`,
  `[http-8]`), `tests/unit/test_net_connection_parker.cpp` (`[net][http-1]`).
* `docs/http-transport.md`, "Connection dispatcher".
