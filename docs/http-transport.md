# HTTP transport

The HTTP transport capability is a narrow Matrix API transport boundary, not a
general web framework.

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
- single-request HTTP/1.1 adapter from parsed request heads to client-server
  Matrix JSON handlers
- production-named client-server API boundary in `client_server.hpp`
- slowloris progress policy scaffolding
- per-endpoint rate-limit policy scaffolding
- HTTP request-head fuzz target
- TCP listener and accept loop via `merovingian::net::TcpAcceptor`
- RAII signal-safe shutdown via `merovingian::net::ShutdownSignal` (SIGINT, SIGTERM)
- per-connection request read, parse, and dispatch via `merovingian::homeserver::serve_http`
- dispatch-mode separation so client listeners use the Matrix JSON
  `client_server` adapter while federation/internal compatibility paths can
  keep using the local router
- OpenSSL-backed TLS server context and connection wrappers
- TLS listener accept path with bounded handshake timeout
- single-mutex serialisation of runtime mutation across acceptors

Not implemented yet:

- `llhttp` dependency wrapper
- request body streaming implementation
- per-endpoint rate-limit enforcement
- runtime application of the slowloris progress policy
- HTTP/2
- keep-alive (every connection currently sends `Connection: close`)

## TLS listener boundary

TLS is a runtime listener boundary, not a replacement for the HTTP parser. The
listener accepts TCP, upgrades the accepted socket through
`merovingian::homeserver::TlsServerContext`, then passes a stream abstraction to
the same bounded HTTP/1.1 request path used by cleartext loopback listeners.

TLS startup fails closed when OpenSSL cannot initialise, load the certificate
chain, load the private key, or verify that the private key matches the
certificate. Handshakes use a bounded timeout aligned with the current
per-connection read deadline. The server currently enforces TLS 1.2 or newer and
keeps connection lifetime to a single HTTP request.

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
