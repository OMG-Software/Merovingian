# src/http/ — HTTP Transport Module

Low-level HTTP request/response handling, rate limiting, and outbound connections.
This module has no Matrix-specific logic — it is a transport layer only.

## Key files

| File | Responsibility |
|---|---|
| `request.cpp` | `RequestHead` parsing: request line, header name/value validation, `Content-Length` handling, parse-error → status mapping |
| `request_limits.cpp` | `ClientApiLimits` — per-client rate-limit and body-size caps |
| `rate_limit.cpp` | Token-bucket rate limiter; applied per IP before dispatching requests |
| `connection_guard.cpp` | `SlowlorisPolicy` — slow-request detection and per-phase (awaiting / reading) connection close decisions |
| `keep_alive.cpp` | `KeepAlivePolicy` — idle timeout and the `max_connections` cap on parked keep-alive connections; `Connection` header handling |
| `outbound_client.cpp` | Performs outbound HTTPS requests against a pre-resolved, pinned address |

`include/merovingian/http/server.hpp` declares an `http::Server` class that has no
implementation and no users. The listening server lives in `homeserver/http_server.cpp`.

## Rules

- **Rate limiting is applied before any auth check** — don't move it after auth, that would
  allow unauthenticated callers to exhaust server resources.
- **Header lookup is case-insensitive.** The client-server dispatcher's `request_header(req, name)`
  (in `homeserver/client_server.cpp`, over `LocalHttpRequest`) is the lookup to use; never compare
  header names with a case-sensitive match.
- **`outbound_client` does not resolve hosts.** `perform()` requires `pinned_addresses` and binds
  them with `CURLOPT_RESOLVE`, so the SSRF policy in `federation::security` stays the single
  source of truth. Resolve server names through `federation/server_discovery.cpp` first, then
  call `outbound_client.hpp`; do not make ad-hoc HTTP calls from other modules.
- Body size limits are per-endpoint; see `homeserver/AGENTS.md` for the media upload exception.

## Key doc

- `docs/http-transport.md` — rate limiting, body caps, TLS, connection management
