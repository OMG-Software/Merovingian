# HTTP transport

The Phase 3 HTTP transport scaffolding is a narrow Matrix API transport boundary, not a general web framework.

## Current scope

Implemented now:

- conservative HTTP request limits
- request-line size checks
- header byte limits
- header count limits
- method token validation
- request target validation
- bounded HTTP/1.1 request-head parsing
- structured request error codes
- content-length validation
- transfer-encoding rejection until streaming support exists
- slowloris progress policy scaffolding
- per-endpoint rate-limit policy scaffolding
- HTTP request-head fuzz target
- TCP listener and accept loop via `merovingian::net::TcpAcceptor`
- RAII signal-safe shutdown via `merovingian::net::ShutdownSignal` (SIGINT, SIGTERM)
- per-connection request read, parse, and dispatch into the local HTTP router via `merovingian::homeserver::serve_http`
- single-mutex serialisation of runtime mutation across acceptors

Not implemented yet:

- TLS provider integration (TLS listeners fail closed at startup)
- `llhttp` dependency wrapper
- request body streaming implementation
- per-endpoint rate-limit enforcement
- runtime application of the slowloris progress policy
- HTTP/2
- keep-alive (every connection currently sends `Connection: close`)

## Request limits

Default request limits are intentionally conservative:

| Limit | Default |
| --- | ---: |
| Start line | 8192 bytes |
| Headers | 32768 bytes |
| Header count | 100 |
| Body | 1048576 bytes |

The parser rejects oversized or malformed request heads before any endpoint handling.

## Structured errors

Request parser failures use stable error names and HTTP statuses. Oversized start lines, headers, header counts, and bodies map to `413`. Malformed request lines, invalid methods, invalid targets, and invalid content lengths map to `400`. Unsupported transfer encoding maps to `501` until streaming support exists.

## Slowloris policy

The slowloris guard tracks bytes received versus elapsed time using:

- minimum bytes per second
- grace period
- header deadline

This is currently a pure policy primitive. Runtime socket code must apply it when connection I/O exists.

## Rate-limit policy

Endpoint default policies are intentionally simple and conservative:

| Endpoint class | Default |
| --- | --- |
| Login / registration | 5 requests / 60 seconds |
| Device and key APIs | 30 requests / 60 seconds |
| Media APIs | 20 requests / 60 seconds |
| Federation APIs | 120 requests / 60 seconds |
| Generic APIs | 60 requests / 60 seconds |

This is a policy primitive only. Runtime accounting and persistence are future work.

## Fuzzing

`fuzz-http-request` exercises the request-head parser against arbitrary input. It is registered with the existing fuzz target group.
