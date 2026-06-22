# src/http/ — HTTP Transport Module

Low-level HTTP request/response handling, rate limiting, and outbound connections.
This module has no Matrix-specific logic — it is a transport layer only.

## Key files

| File | Responsibility |
|---|---|
| `request.cpp` | `Request` struct — method, target, body, headers; `request_header()` case-insensitive lookup |
| `request_limits.cpp` | `ClientApiLimits` — per-client rate-limit and body-size caps |
| `rate_limit.cpp` | Token-bucket rate limiter; applied per IP before dispatching requests |
| `connection_guard.cpp` | RAII guard that tracks active connections; enforces `max_connections` |
| `outbound_client.cpp` | Makes outbound HTTPS requests (used by federation and server discovery) |

## Rules

- **Rate limiting is applied before any auth check** — don't move it after auth, that would
  allow unauthenticated callers to exhaust server resources.
- **`request_header(req, name)` is case-insensitive.** Always use it for header lookup; never
  do `req.headers["Content-Type"]` directly, which is case-sensitive.
- **`outbound_client` follows the Matrix server discovery protocol** — do not make ad-hoc HTTP
  calls from other modules. Route all outbound federation requests through `outbound_client.hpp`.
- Body size limits are per-endpoint; see `homeserver/AGENTS.md` for the media upload exception.

## Key doc

- `docs/http-transport.md` — rate limiting, body caps, TLS, connection management
