# src/http/ — HTTP Transport Module

Low-level HTTP request/response handling, rate limiting, and outbound connections.
This module has no Matrix-specific logic — it is a transport layer only.

## Key files

| File | Responsibility |
|---|---|
| `request.cpp` | `RequestHead` parsing: request line, header name/value validation, `Content-Length` handling, parse-error → status mapping |
| `RequestLimits.cpp` | `ClientApiLimits` — per-client rate-limit and body-size caps |
| `rate_limit.cpp` | Token-bucket rate limiter; applied per IP before dispatching requests |
| `connection_guard.cpp` | `SlowlorisPolicy` — slow-request detection and per-phase (awaiting / reading) connection close decisions (a policy function; the listener enforces the same composition through the connection dispatcher, ADR-0077) |
| `ConnectionLimiter.cpp` | `ConnectionLimiter` — per-client cap on open connections, applied at accept time (ADR-0072); RAII `Slot` |
| `client_address.cpp` | `client_address_key` — the key per-client limits count under (IPv6 grouped by prefix); shared by the connection cap and the rate limiter |
| `keep_alive.cpp` | `KeepAlivePolicy` — idle timeout and the `max_connections` cap on parked keep-alive connections (held by the connection dispatcher, not by worker threads); `Connection` header handling |
| `OutboundClient.cpp` | Performs outbound HTTPS requests against a pre-resolved, pinned address |
| `InFlightBudget.cpp` | `InFlightBudget` — admission guard bounding work in flight process-wide and per client key; `try_acquire` answers at once, never queues; RAII `Slot` and `Waiter` (ADR-0079, ADR-0310) |
| `library_versions.cpp` | Reports the libcurl version (running and build-time) for the start-up log |

`include/merovingian/http/Server.hpp` declares an `http::Server` class that has no
implementation and no users. The listening server lives in `homeserver/http_server.cpp`.

## Rules

- **Rate limiting is applied before any auth check** — don't move it after auth, that would
  allow unauthenticated callers to exhaust server resources.
- **Header lookup is case-insensitive.** The client-server dispatcher's `request_header(req, name)`
  (in `homeserver/ClientServerRuntime.cpp`, over `LocalHttpRequest`) is the lookup to use; never compare
  header names with a case-sensitive match.
- **`outbound_client` does not resolve hosts.** `perform()` requires `pinned_addresses` and binds
  them with `CURLOPT_RESOLVE`, so the SSRF policy in `federation::security` stays the single
  source of truth. Resolve server names through `federation/server_discovery.cpp` first, then
  call `OutboundClient.hpp`; do not make ad-hoc HTTP calls from other modules.
- **`outbound_client` refuses invalid header fields before any I/O (ADR-0180).** A name must be an
  RFC 9110 token and a value must hold no control character other than HTAB; anything else is
  `OutboundError::invalid_header`. Header values carry client input (an identity server access
  token), and libcurl writes header lines verbatim. Keep the check in both
  `validate_outbound_request` and `perform`.
- **`outbound_client` logs a URL without its query (F-76, ADR-0418).** The `url` field of
  `request.success`, `request.error` and `request.redirect_rejected` is `loggable_url`: scheme, host,
  port and path. A query can hold an identity server's `client_secret` or a user's URL. A new log site
  in this file uses the same string.
- Body size limits are per-endpoint; see `homeserver/AGENTS.md` for the media upload exception.
- **Per-client limits share one key.** `client_address_key` is the key for the per-IP connection
  cap (ADR-0072), the per-client worker share (ADR-0077) and the rate limiter. The first two use the
  TCP peer and exempt `server.trusted_proxies`; a new per-client limit should use the same key and
  say which address it keys on.
- The listener lives in `homeserver/http_server.cpp`: no worker waits on a quiet connection (the
  connection dispatcher does), request bodies are bounded by a minimum rate (16 KiB/s after 10 s),
  and a connection closes after 1 000 requests or an hour. See `docs/http-transport.md`.

## Key doc

- `docs/http-transport.md` — rate limiting, body caps, TLS, connection management
