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
- OpenSSL-backed TLS server context and connection wrappers, with OpenSSL
  resolved from the operating-system package
- TLS listener accept path with bounded handshake timeout
- single-mutex serialisation of runtime mutation across acceptors
- self-sufficient CORS emission: every response carries
  `Access-Control-Allow-Origin` and `Vary: Origin`; `OPTIONS` preflight
  responses additionally carry `Access-Control-Allow-Methods`,
  `-Headers`, and `-Max-Age` derived from the runtime's `server.cors.*`
  config (0.4.60 preflight; 0.5.30 extended to all non-OPTIONS
  responses via a single `handle_client_server_request` boundary).
  Reverse proxies must not add their own CORS headers; see
  `docs/configuration.md` Reverse proxy examples.
- response-header validation at both the client-server header assembler and
  final wire formatter, dropping invalid header names/values instead of
  emitting them on the wire
- `X-Content-Type-Options: nosniff` on every response

Not implemented yet:

- `llhttp` dependency wrapper
- request body streaming implementation
- per-endpoint rate-limit enforcement
- runtime application of the slowloris progress policy
- HTTP/2
- keep-alive (every connection currently sends `Connection: close`)

## Response-header safety

Runtime-generated response headers are validated with the shared HTTP header
grammar before they are stored or written to the wire. This prevents CR/LF and
other invalid octets from being reflected through CORS or future dynamic header
surfaces. The wire formatter also injects `X-Content-Type-Options: nosniff`
when the response did not already set it.

## Outbound HTTP client

`merovingian::http::OutboundClient` is the federation outbound HTTP boundary.

The public surface comprises `OutboundRequest`, `OutboundResponse`,
`OutboundResult`, `OutboundError`, the pure `validate_outbound_request`
helper, and the `OutboundClient` class itself. The client is stateless and
holds no per-instance resources; operations report failures through
`OutboundResult` rather than exceptions.

A single `OutboundClient` instance is safe to share across threads. The
runtime hands one instance to both the federation dispatch-worker thread and
the HTTP request-handler thread pool. A libcurl easy handle must never be
driven by more than one thread at a time, so `perform()` uses a per-thread
handle: each thread lazily creates its own handle on first use and frees it at
thread exit. Because every call resets the handle before configuring it, the
handle is reused across calls (preserving per-thread connection and
TLS-session reuse) without leaking state between requests. Sharing a single
handle across threads previously caused intermittent `network_error` failures
on federation key queries that broke E2EE.

The validator enforces the security invariants that hold regardless of
backend choice:

- the request method must be a known token (`GET`, `POST`, `PUT`, `DELETE`)
- the URL must be an absolute `https://` URL with a host segment
- at least one address must be supplied in `pinned_addresses`; the client
  does not resolve hostnames so the SSRF policy in
  `merovingian::federation::security` remains the single source of truth

`perform()` is libcurl-backed. Each request runs with the following
non-negotiable defaults so federation traffic cannot regress its security
posture:

- `CURLOPT_SSL_VERIFYPEER = 1` — reject untrusted certificate chains
- `CURLOPT_SSL_VERIFYHOST = 2` — require the certificate to match the URL host
- `CURLOPT_FOLLOWLOCATION = 0` — redirects are refused
- `CURLOPT_PROTOCOLS_STR = "https"` — no cleartext fallback
- `CURLOPT_NOSIGNAL = 1` — signal-driven resolution disabled so timeouts
  remain safe across threads
- `CURLOPT_CONNECTTIMEOUT` and `CURLOPT_TIMEOUT` driven by the request
  fields
- `CURLOPT_RESOLVE` populated from `pinned_addresses` so the connection
  is locked to addresses validated by the federation security policy

The response body is captured up to `max_response_body_bytes`. Oversized
responses abort the transfer and surface as `response_too_large`. A 3xx
response surfaces as `redirect_rejected` with the status and headers
preserved on the result for audit logging.

libcurl error codes map onto `OutboundError`: TLS verification failures
collapse to `tls_verification_failed`, connect/resolve failures to
`connection_failed`, timeouts to `timeout`, and the catch-all is
`network_error`.

The TLS backend is whatever the system libcurl was built against. A
per-platform integration suite (Linux, FreeBSD, OpenBSD) is wired up in
slice 3 alongside the federation outbound transaction integration so
backend drift surfaces in CI rather than at runtime. The
`subprojects/curl.wrap` fallback is deferred until a known-good WrapDB
release is pinned.

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

OpenSSL is the selected TLS provider for this boundary. The project-owned
wrapper keeps OpenSSL-specific types out of higher-level transport code, which
contains provider maintenance without making provider replacement part of the
current plan. OpenSSL is dynamically linked from the host package manager so
TLS security updates can arrive through normal distro and BSD package channels.

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
