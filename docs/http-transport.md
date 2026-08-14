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
- accepted client sockets (both plain-HTTP and TLS accept loops in
  `http_server.cpp`) are created with `accept4(..., SOCK_CLOEXEC)`, matching
  the listening socket, so they cannot leak into a `posix_spawn`/`fork()`ed
  worker subprocess (federation worker, thumbnail worker) while a connection
  — e.g. a long-poll `/sync` — is still open
- RAII signal-safe shutdown via `merovingian::net::ShutdownSignal` (SIGINT, SIGTERM)
- per-connection request read, parse, and dispatch via `merovingian::homeserver::serve_http`
- dispatch-mode separation so client listeners use the Matrix JSON
  `client_server` adapter while federation/internal compatibility paths can
  keep using the local router
- OpenSSL-backed TLS server context and connection wrappers, with OpenSSL
  resolved from the operating-system package
- TLS listener accept path with bounded handshake timeout
- per-room striped mutex serialisation of runtime mutation (256-way stripe
  keyed by room ID; see [`docs/architecture.md`](architecture.md) "Per-room
  inbound PDU ingestion") so independent rooms can prepare, commit, and apply
  concurrently instead of serialising on one global mutex
- a dedicated `sync_pool` (32 threads by default) separate from the main
  request pool, so long-polling `/sync` clients cannot starve federation and
  other short-lived requests
- self-sufficient CORS emission: every response carries
  `Access-Control-Allow-Origin` and `Vary: Origin`; `OPTIONS` preflight
  responses additionally carry `Access-Control-Allow-Methods`,
  `-Headers`, and `-Max-Age` derived from the runtime's `server.cors.*`
  config (0.4.60 preflight; 0.5.30 extended to all non-OPTIONS
  responses via a single `handle_client_server_request` boundary).
  Reverse proxies must not add their own CORS headers; see
  `docs/user-manual.md` Reverse proxy section.
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

The response body is captured up to `max_response_body_bytes`. The write
callback guards against unsigned underflow: it checks `body.size() >= cap`
before evaluating `bytes > cap - body.size()`, preventing wrap-around when
the accumulated body already meets the cap. Oversized responses abort the
transfer and surface as `response_too_large`. A 3xx
response surfaces as `redirect_rejected` with the status and headers
preserved on the result for audit logging.

Response headers are likewise capped (issue #413): at most 256 headers and
64 KiB of cumulative header bytes are stored; libcurl imposes no default
limit on either, so a hostile peer streaming an unbounded header count could
otherwise trigger a `bad_alloc` that escapes the `noexcept` header callback
and calls `std::terminate`, aborting the whole process. Exceeding either cap
aborts the transfer (`response_too_large`); allocation failures inside the
callback are also caught and mapped the same way instead of propagating.

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

### Identity Service API client

The `identity` module's `IdentityServerClient` is a client of the Matrix
Identity Service API, not a federation peer, so it authenticates with a
bearer `id_access_token` (not `X-Matrix` federation auth). It issues
`store-invite` (third-party invite issuance), `lookup`, `bind`, `unbind`,
and `requestToken` calls to a remote identity server over the same
SSRF-safe `OutboundClient` + `CachedServerDiscovery` resolver used for
federation: hostnames resolve through `CachedServerDiscovery` with pinned
addresses, and private/loopback addresses are rejected so a misconfigured
or hostile IS hostname cannot redirect the homeserver onto an internal
network. Trusted IS hosts are configured via
`server.identity_server.trusted_servers`; the homeserver fails closed
(403) when an `id_server` named in a 3PID invite is not in that list. The
`store-invite` call is performed outside `runtime.mutex` so an unreachable
identity server cannot block unrelated room mutations. The same resolver,
trust gate, bearer-auth, fail-closed, and release-`mutex`-for-network conventions
apply to the `bind`, `unbind`, and `requestToken` handlers (v0.11.10); see
`docs/auth-identity.md`.

#### Identity discovery test-seam (`test_forced_identity_resolution`)

`IdentityServerClient` accepts an optional
`std::map<std::string, identity::TestForcedIdentityResolution> const*
forced_resolution` (defined in `include/merovingian/identity/identity_client.hpp`,
stored on `HomeserverRuntime::test_forced_identity_resolution` and keyed by IS
host). When an entry exists for the target host, `perform()` uses the entry's
`pinned_addresses` and in-memory `trusted_ca_pem` and skips
`CachedServerDiscovery` entirely, so a self-signed local mock IS listening on
`127.0.0.1` can be reached over real TLS without weakening the production SSRF
path — the map is empty in production and has no production construction path.
Unlike the federation seam, the identity seam carries no `resolved_port`: the IS
base URL already names the port, and `OutboundClient` builds the `CURLOPT_RESOLVE`
entry `host:port:address` from the URL's host:port and the seam's address, so the
mock IS port must match the URL/id_server the homeserver is configured to call.
This keeps the `homeserver → identity` dependency direction correct (the seam
struct lives in the identity header, not `runtime.hpp`) and lets the
conformance/integration suites exercise `store-invite`, `bind`, `unbind`, and
`requestToken` hermetically.

## TLS listener boundary

TLS is a runtime listener boundary, not a replacement for the HTTP parser. The
listener accepts TCP, upgrades the accepted socket through
`merovingian::homeserver::TlsServerContext`, then passes a stream abstraction to
the same bounded HTTP/1.1 request path used by cleartext loopback listeners.

Configuration enforces TLS on any public (non-loopback) listener. A loopback
listener may only run in cleartext when the operator explicitly declares it is
behind a local reverse proxy (`reverse_proxy=true`). Public listeners must set
`reverse_proxy=false`.

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

Runtime rate limiting is enforced on every client-server and inbound federation
request before dispatch. Two independent wall-clock token-bucket tiers are
maintained:

- **Per-IP**, keyed by `(effective_client_ip, normalized_route)`.
- **Per-user**, keyed by `(authenticated_user_id, normalized_route)` for
  requests that present a valid access token.

A quiet server does not freeze a bucket because the window rolls over on elapsed
real time, not on request count. When a cap is exceeded the server returns
`429 M_LIMIT_EXCEEDED` with a `Retry-After` header (seconds). The deprecated
`retry_after_ms` body field is also included for older clients.

Default route-aware policies use longest-prefix matching. Path parameters such as
`roomId`, `deviceId`, and `mediaId` are coalesced into placeholders so the same
cap applies regardless of which room, device, or media ID appears in the URL:

| Endpoint class | Default policy |
| --- | --- |
| Login / registration | 20/60s per IP; 5/60s per user on `/login` |
| Device and key APIs | 30/60s per IP |
| Media APIs | 20/60s per IP |
| Search API (`/_matrix/client/v3/search`) | 20/60s per IP — same tier as media; each request does real work (a bounded in-memory scan, see `ClientApiLimits::max_search_events_scanned`) rather than a cheap lookup |
| Federation APIs | 120/60s per IP |
| Admin routes (`/_merovingian/admin/*`) | 30/60s per IP |
| Generic client APIs | 90/60s per IP fallback |

Operators override any class via `client_rate_limits.per_ip.<target>` and
`client_rate_limits.per_user.<target>`; `client_rate_limits.default_per_ip` is
the fallback for unmatched targets. All policy changes require a server restart.
`window_seconds` must be `1..3600` — both `rate_limit_policy_is_valid()` (engine)
and config validation reject anything outside that range.

**Fail-closed on an unresolvable policy (issue #412):** if both the per-IP and
per-user policies resolve to `nullopt` (e.g. an operator-configured
`default_per_ip` with `window_seconds > 3600`), `RateLimitEngine::check()`
denies the request rather than allowing it — a misconfigured policy must never
silently disable rate limiting.

**Bounded bucket tables (issue #427):** `m_ip_buckets`/`m_user_buckets` are
hash maps capped at 100,000 entries each, with stale-entry and
least-recently-touched eviction, so a client rotating a spoofable
`X-Forwarded-For` value (see below) cannot grow the table or the per-check
cost without bound.

### Admin routes

`/_merovingian/admin/*` (health, metrics, audit, media moderation) is served on
the public client listener. The client-server dispatcher routes the
`/_merovingian/admin/` prefix to the local router **before** the general
user-token gate, so `require_admin()` owns the auth outcome: 401
`M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN` for a missing or invalid token, 403
`M_FORBIDDEN` for a valid token belonging to a non-admin user. The routes
inherit the same `allow()` rate-limit gate as every other client-server
request — throttled exactly once per request, no double-count — under the
`/_merovingian/admin/` per-IP prefix policy (30/60s by default, operator-tunable
via `client_rate_limits.per_ip`). Operator-only and low-volume, but still
throttled against brute-force token guessing.

### In-memory counter trade-off

Rate-limit counters live entirely in process memory (`m_ip_buckets` /
`m_user_buckets` on the `RateLimitEngine`). They are **not** persisted: there is
no per-request database write to update a counter, by design. The trade-off is
that a restart (or a worker crash under a federated deployment) resets the
counters, so a client that was being throttled can immediately retry. This is
an accepted operator sign-off: the cost of a per-request durable write — and
the latency and contention a shared counter table would add to the hottest path
in the server — is not worth the marginal benefit, because rate limiting is a
best-effort abuse throttle rather than a hard correctness invariant. If a
durable cap is required for a specific route, an operator should front the
homeserver with a proxy that enforces it.

### Trusted-proxy client IP resolution

When the direct TCP peer's address is listed in `server.trusted_proxies`, the
client-server rate limiter keys on the leftmost non-empty value in
`X-Forwarded-For` instead of the peer address, so the entire downstream
network isn't collapsed into one bucket. That value is validated as a real
IPv4 or IPv6 literal (`federation::ip_address_is_valid()`) before it is
trusted — a trusted proxy is only trusted to forward its own view of the
client address correctly, not to hand the server an arbitrary string. If the
header is missing, empty, or not a valid IP literal, the limiter falls back to
the direct peer address rather than trusting it verbatim. Without this check,
an attacker able to reach a trusted proxy (or a proxy that fails to overwrite
an inbound `X-Forwarded-For` header) could rotate through malformed
pseudo-IP values to mint a fresh rate-limit bucket per request and defeat
per-IP limiting on `/login`, `/register`, and every other endpoint entirely.

## Sync long-poll thread pool

`/sync` long-polls are dispatched to a dedicated `sync_pool` (32 threads),
separate from the main request pool (8 threads) that serves every other
client-server and federation request. This split exists because a burst of
long-polling clients on the main pool could previously exhaust it entirely,
starving federation and other short-lived requests. See
[`docs/architecture.md`](architecture.md) "Runtime model" for the full pool
layout and [`src/sync/AGENTS.md`](../src/sync/AGENTS.md) for sync-specific
conventions.

## Fuzzing

`fuzz-http-request` exercises the request-head parser against arbitrary input. It is registered with the existing fuzz target group.
