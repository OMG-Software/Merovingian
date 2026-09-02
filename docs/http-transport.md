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
- HTTP/1.1 persistent connections (keep-alive, RFC 9112 §9.3): sequential
  request rounds over one connection, per-request framing with exact
  Content-Length body draining, an operator-tunable idle window, and a
  process-wide parked-connection cap — see "HTTP keep-alive" below

Not implemented yet:

- `llhttp` dependency wrapper
- request body streaming implementation
- per-endpoint rate-limit enforcement
- runtime application of the slowloris progress policy to the request-head
  read deadline (the head deadline and inter-byte caps in `http_server.cpp`
  are the inline enforcement of that policy)
- HTTP/2
- HTTP pipelining (more than one outstanding request per connection):
  pipelined bytes are buffered and answered strictly in order, one response
  at a time, so request boundaries are never lost

## HTTP keep-alive

Matrix v1.19 is served over HTTP/1.1, where persistent connections are the
default. Merovingian serves each connection as a sequential loop of request
rounds (`serve_connection` in `src/homeserver/http_server.cpp`): read one
request head, drain exactly its Content-Length bytes, route, write one
response, then either close or park the connection for the next request.

Framing decisions (RFC 9112 §9.3, implemented in
`merovingian::http::connection_preference_for_response`):

- HTTP/1.1 requests default to `Connection: keep-alive`; a request carrying
  the `close` token is answered with `Connection: close` and the connection
  is closed after that response.
- HTTP/1.0 requests default to close; only a request carrying the
  `keep-alive` token keeps the connection open.
- Kept-alive responses carry `Connection: keep-alive` and the advisory
  `Keep-Alive: timeout=N` hint matching the configured idle window. The hint
  is not a promise: the server may still close early (parked-connection cap
  reached, shutdown) and the client must retry on a new connection.

Connection lifecycle:

1. **First request** — served immediately after accept; no parking, so no
   worker thread is held without work.
2. **Idle park** — before waiting for a subsequent request the connection
   acquires one process-wide parked slot (CAS counter,
   `parked_keep_alive_connections`). Beyond `server.http.keep_alive_max_connections`
   the server closes after the current response instead of parking. The park
   is bounded by `server.http.keep_alive_idle_seconds`, polled in one-second
   slices so pool shutdown stays bounded to one slice regardless of the
   configured window.
3. **Next request** — when bytes arrive, the slot is released and the full
   per-request machinery (slowloris head deadline and inter-byte caps, body
   size caps, rate limits) applies to that request exactly as for a fresh
   connection. Bytes read past a request's body (pipelined follow-up
   requests) are carried into the next round, so request boundaries are
   never lost.

Slowloris composition: the phase-aware `connection_should_close` guard
(`include/merovingian/http/connection_guard.hpp`) distinguishes
`awaiting_request` (parked, bounded only by the idle window — a quiet
connection is not a slow client) from `reading_request` (the slowloris
rate policy applies in full). Mid-request slow clients are killed exactly as
before; idle kept-alive connections are not.

Sync-pool interaction: a `/sync` long-poll round is handed to the dedicated
sync pool as before. When the long-poll response has been written and the
client asked for keep-alive, the sync task submits the connection back to the
main pool for its next round, preserving the pool separation (long-poll
threads never serve ordinary request rounds).

Configuration (`server.http.*`, restart required — read when listeners start):

| Key | Default | Meaning |
|---|---|---|
| `server.http.keep_alive` | `true` | Enable persistent connections. `false` restores one-request-per-connection. |
| `server.http.keep_alive_idle_seconds` | `15` | Idle window per parked connection, 1..300. |
| `server.http.keep_alive_max_connections` | `8` | Process-wide cap on connections parked awaiting a request, 1..4096. Each parked connection occupies a main-pool worker thread. |

Direct `serve_one_http_connection` callers (tests, one-off embeds) keep the
historical one-request-per-call contract: with no owning pool the policy
disables parking and the round is answered with `Connection: close`.

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

**`OutboundRequest::allow_cleartext_http`** (added 0.12.1) is a narrow,
opt-in escape hatch from the https-only rule above, defaulting to `false`
for every existing caller (federation, the push-gateway client, the
identity-server client all stay https-only with no way to override it).
Setting it to `true` additionally permits `http://` for that one request.
The only sanctioned caller is `appservice::AppserviceClient`
(`src/appservice/appservice_client.cpp`): an appservice registration file's
`url` is operator-configured — a local filesystem artifact the operator
wrote, not something a network peer can influence — and the Application
Service API's own canonical registration example (and most real-world
bridges) gives a plain `http://127.0.0.1:...` URL. When set, host
resolution also intentionally bypasses `CachedServerDiscovery`'s
private/loopback-address rejection (via `.upstream().lookup_addresses()`
directly) for the same reason: that rejection exists specifically for
attacker/client-influenced destinations, which an appservice URL is not.
TLS verification (`CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST`) is unaffected —
still on unconditionally whenever the connection does end up being TLS.

`perform()` is libcurl-backed. Each request runs with the following
non-negotiable defaults so federation traffic cannot regress its security
posture:

- `CURLOPT_SSL_VERIFYPEER = 1` — reject untrusted certificate chains
- `CURLOPT_SSL_VERIFYHOST = 2` — require the certificate to match the URL host
- `CURLOPT_FOLLOWLOCATION = 0` — redirects are refused
- `CURLOPT_PROTOCOLS_STR = "https"` — no cleartext fallback, unless the
  request set `allow_cleartext_http = true` (see above), in which case
  `"https,http"`
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

The request-head read applies the equivalent deadlines inline (`request_head_deadline`, inter-byte cap, per-`recv` poll timeout in `http_server.cpp`); a request head that dribbles bytes is dropped with a 408 once any bound is exceeded.

Keep-alive parking composes with the guard phase-aware
(`connection_should_close`): a connection `awaiting_request` (parked, no
bytes in flight) is bounded only by the keep-alive idle window, never by the
slowloris rate — a quiet connection is not a slow client. A connection
`reading_request` is subject to the full slowloris policy.

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
`retry_after_ms` body field is also included for older clients. A 429 does not
tear down a keep-alive connection: connection framing is decided per request
round and is status-independent (see "HTTP keep-alive" above), so a throttled
client can wait out its window on the same connection and retry.

### Route tiers

Every client-server route is classified into one of six explicit tiers by the
prefix table in `http::rate_limit_tier_for()` (`src/http/rate_limit.cpp`) — one
greppable place, no magic. Path parameters such as `roomId`, `deviceId`, and
`mediaId` are coalesced into placeholders by `normalized_target()` so the same
cap applies regardless of which room, device, or media ID appears in the URL.

| Tier | Routes | Default per-IP policy |
| --- | --- | --- |
| `auth_sensitive` | `/login`, `/register`, `/refresh`, and every `*/requestToken` route (matched by suffix) — unauthenticated, so the per-IP bucket is the only defense | 20/60s |
| `media` | `/_matrix/media/*` and `/_matrix/client/v1/media/*` | 20/60s |
| `sync` | `/sync` plus the MSC4186 and simplified MSC3575 sliding-sync long-polls | 90/60s |
| `federation` | `/_matrix/federation/*` routes reaching the client-server dispatcher | 120/60s |
| `admin` | `/_merovingian/admin/*` | 30/60s |
| `generic` | every other client-server route | `client_rate_limits.default_per_ip` (90/60s) |

Built-in per-endpoint refinements inside a tier: device and key APIs at
30/60s, search at 20/60s — each request does real work (a bounded in-memory
scan, see `ClientApiLimits::max_search_events_scanned`) rather than a cheap
lookup. The built-in per-user cap is 5/60s on `/login`.

The per-user tier keys on the *authenticated* user, which before a login
succeeds is nobody — so a `/login` guessing spree against one account spread
across many source IPs previously accumulated against nothing at all,
regardless of tier. There is now an additional, independent per-account
failed-login throttle layered on top of these IP/user buckets, tracking
failures against the claimed user ID rather than an IP or an authenticated
identity; see `docs/auth-identity.md` "Per-account failed-login throttle"
for the mechanism, thresholds, and trade-offs.

Classification is method-agnostic: a `GET` against `/login` is the same
enumeration surface as a `POST`, and the `*/requestToken` family spans several
path parents, so it is matched by suffix.

### Operator overrides

Per-IP policy resolution is most-specific-first:

1. `client_rate_limits.per_ip.<target-prefix>` (longest prefix match wins),
2. `client_rate_limits.tier.<name>` for the route's tier,
3. the built-in per-endpoint refinement (keys/devices 30/60s, search 20/60s),
4. the tier default; the `generic` tier resolves to
   `client_rate_limits.default_per_ip`.

Per-user resolution: `client_rate_limits.per_user.<target-prefix>` first, then
the built-in 5/60s login cap; routes with neither have no per-user cap (the
per-IP cap still applies). Tier names are `auth_sensitive`, `media`, `sync`,
`federation`, `admin`, `generic`; an unknown name is a parse-time finding, not a
silently ignored key. All `client_rate_limits.*` changes require a server
restart. `window_seconds` must be `1..3600` — both `rate_limit_policy_is_valid()`
(engine) and config validation reject anything outside that range.

Defaults remain the operator-agreed secure values from the 0.5.0 design doc;
tiering only makes them explicit and complete. One deliberate tightening: the
auth-sensitive tier now covers `/refresh`, the `*/requestToken` family, and
non-`POST` hits on `/login`/`/register`, which previously fell into the 90/60s
generic fallback.

**Fail-closed on an unresolvable policy (issue #412):** the per-IP policy
resolves to a value on every route unless a configured entry, tier override, or
the default fails `rate_limit_policy_is_valid()` (e.g.
`window_seconds > 3600`). An unresolvable per-IP policy makes
`RateLimitEngine::check()` deny the request — even when a valid per-user policy
exists, because the per-IP bucket is the only defense on unauthenticated
routes. A misconfigured policy must never silently disable rate limiting.

**Bounded bucket tables (issue #427):** `m_ip_buckets`/`m_user_buckets` are
hash maps capped at 100,000 entries each, with stale-entry and
least-recently-touched eviction, so a client rotating a spoofable
`X-Forwarded-For` value (see below) cannot grow the table or the per-check
cost without bound.

### Inbound federation

`/send` transactions are limited per **verified origin server name** (the
X-Matrix-authenticated peer, not the IP) by a weighted trio:
`security.federation.per_origin_transaction_rate` (120/60s),
`per_origin_pdu_rate` (600/60s), `per_origin_edu_rate` (1200/60s). Every other
inbound federation endpoint (query, backfill, membership, key and state routes)
is limited by `security.federation.per_origin_request_rate` (600/60s), checked
after signature verification and the server-ACL check, before dispatch.
Non-`/send` traffic is counted only against `per_origin_request_rate` and
`/send` only against the weighted trio, so a transaction and its contents are
never double-counted.

### Admin routes

`/_merovingian/admin/*` (health, metrics, audit, media moderation) is served on
the public client listener. The client-server dispatcher routes the
`/_merovingian/admin/` prefix to the local router **before** the general
user-token gate, so `require_admin()` owns the auth outcome: 401
`M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN` for a missing or invalid token, 403
`M_FORBIDDEN` for a valid token belonging to a non-admin user. The routes
inherit the same `allow()` rate-limit gate as every other client-server
request — throttled exactly once per request, no double-count — under the
admin-tier default (30/60s, operator-tunable via
`client_rate_limits.tier.admin` or a per-prefix entry). Operator-only and
low-volume, but still throttled against brute-force token guessing.

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

## Request lock and blocking network calls

Both request entry points — `handle_client_server_request` and
`handle_local_http_request` — take `HomeserverRuntime::mutex` for the whole
request. That single mutex also guards inbound federation handling, so anything
holding it blocks every other client and every inbound `/send` transaction.

A synchronous outbound call made while holding it therefore stalls the whole
process for the length of the remote's timeout. Two paths used to do exactly
that: `POST /_matrix/client/v3/keys/query` (one federation `/user/keys/query`
per remote server, each budgeted `remote_timeout_seconds`) and remote media
download/thumbnail fetches. One unreachable peer was enough to freeze local
reads for 20–44 seconds at a time.

The entry points now publish their guard through
`homeserver::RequestLockScope`, and each blocking network call runs inside a
`homeserver::NetworkIoUnlock` scope that releases the mutex for the round trip
and re-acquires it on exit — including when the call throws. Both types live in
[`include/merovingian/homeserver/request_lock.hpp`](../include/merovingian/homeserver/request_lock.hpp).

Rules for anything added to these paths:

- Only the network call goes inside the unlock scope. Reads and mutations of
  runtime state stay outside it, before or after.
- Request signing stays under the lock: `OutboundCall::secret_key` borrows a
  span into the runtime's `SecretBuffer`, which the lock protects.
- The scope is a no-op when no guard is published (the federation worker, a test
  calling a service function directly) or when a caller already released the
  lock by hand, so it composes with the existing `unlock()`/`lock()` pairs.

### `resolve_policy_server_hook` (0.12.1)

`resolve_policy_server_hook` (`src/homeserver/runtime.cpp`) performs a
synchronous outbound call to `trust_safety.policy_server_url` when
`trust_safety.enabled` is set. `handle_federation_http_request` was already
fixed (#415) to call it only after releasing the lock, but three other call
sites called it directly while still holding `HomeserverRuntime::mutex`:
`register_local_user` (client registration), `create_room` (room creation and
room upgrade), and `media_policy_decision` (remote media download and
thumbnail fetch — right before the *already*-unlocked remote fetch call that
follows it). A slow or unreachable policy server therefore still froze every
other client and federation request for up to `policy_server_timeout`,
despite #415.

The fix wraps the remainder of `resolve_policy_server_hook` — the injectable
`trust_safety_policy_server` test hook and the real
`OutboundClient::perform` call alike — in one `NetworkIoUnlock` scope, so
every call site is fixed at the source rather than needing four separate
call-site changes. Everything the function still reads
(`trust_safety_config`, `runtime.config`, the request built from them) is
read before that scope, while the lock is still held; nothing after it
touches runtime state. See `tests/integration/test_request_lock_contention_flow.cpp`
for the regression coverage (registration, room creation, and media
download, each gated on a blocking policy-server hook while an unrelated
request is asserted to complete promptly).

### `NetworkIoUnlock` was incomplete for recursive acquisitions (0.12.1)

`HomeserverRuntime::mutex` is a `std::recursive_mutex` specifically so that a
service function such as `create_room` can take its own lock and remain
independently callable outside a request handler (`local_smoke_flow.cpp` does
exactly this). But `create_room` is *also* called directly from
`client_server.cpp`, which already holds its own outer guard for the whole
request. `std::recursive_mutex` permits that nested acquisition silently — the
same thread simply increments a recursion count — so nothing failed loudly.

The problem: `NetworkIoUnlock` releases exactly one `std::unique_lock`, the
one published via `RequestLockScope`. When the room-creation regression test
above gated `create_room`'s call into `resolve_policy_server_hook`, the
outer guard (published) got released, but `create_room`'s own inner guard —
the second, nested acquisition, and the one actually in lexical scope at the
point of the network call — was never touched. The mutex stayed held by that
thread for the full duration of the (attempted) unlock, and a concurrent
request on another thread blocked forever waiting for the same
`recursive_mutex`. **This means the `NetworkIoUnlock` mechanism, as shipped
in 0.11.13, was correct only for call chains with exactly one lock
acquisition on the stack; it silently did nothing for any chain that passed
through a second, self-locking function.** The room-creation regression test
caught this by deadlocking rather than by a failed assertion — the strongest
possible signal that a lock invariant, not just a status code, was wrong.

Fixed by publishing `RequestLockScope` around `create_room`'s own guard
(`room_service.cpp`) and releasing the caller's outer guard with
`guard.unlock()` before delegating to `create_room` — `guard.lock()`
afterward, when later code still needs the lock — at all three call sites
(`client_server.cpp` ×2: create and room-upgrade; `local_http_router.cpp` ×1).
This is the same unlock/call/relock idiom `local_http_router.cpp` already
used for `join_room`, so `create_room`'s own guard becomes the *only* lock in
scope and the one `NetworkIoUnlock` actually finds and releases.

**`join_room` and `leave_room` have the identical self-locking shape but NOT
the same gap** — checked in 0.12.2, and the suspicion recorded here in 0.12.1
was wrong. Both already release their guard around the federation round trip
with hand-written `guard.unlock()`/`guard.lock()` pairs, so the mutex is not
held across `make_join`/`send_join`/`make_leave`. The regression written to
expose the supposed stall — a remote join against a peer that accepts and
withholds, asserting an unrelated request stays inside the responsiveness
budget — passes against the unfixed code, and is kept so the property cannot
regress silently.

What they do carry is the exception-safety gap common to every hand-written
pair in the codebase: a throw between the release and the re-lock leaves the
guard down and the next request on that thread running unsynchronised. That is
the defect `ScopedGuardRelease` exists to remove, and it is why the remaining
hand-written sites are worth converting even though none of them deadlocks.

`leave_room` is converted (0.12.2): its nine hand-written re-locks are gone and
the whole three-round-trip exchange sits in one scoped release, so the guard is
restored on every exit including a throw.

**That alone did not close the stall**, which review on #485 caught. The client
dispatcher holds its own guard on the same recursive mutex for the duration of
the request, so a release inside `leave_room` drops only the depth the callee
added — the mutex stays held across `make_leave`/`send_leave`. The leave route
therefore releases the dispatcher's guard around the call too, with
`ScopedGuardRelease` rather than a hand-written pair. This is the same failure
shape as `create_room`, found twice by different means, which is why the
remaining hand-written sites are tracked for removal in issue #487 rather than
audited individually. The one value consumed after the
scope — the `send_leave` result, needed by the membership write that must hold
the lock — is declared before it and assigned inside.

**`join_room` is deliberately not converted.** Its released region spans ~350
lines and nine of the forty-four values declared inside it are consumed after
the re-lock (`verified_critical_state`, `verified_auth_chain`, `signed_event`,
`event_id_result` among them). Hoisting those would strip `const` from nine
declarations, require each type to be default-constructible, and split nine
initialisations into declare-then-assign — a real loss of const-correctness
inside a 1019-line function, bought for an exception-safety gain with no live
bug behind it. The correct fix is to extract the released region into its own
function returning a result struct, at which point the scope boundary becomes
the function boundary and nothing needs hoisting. That is a refactor, not a
lock-idiom swap, and is tracked as such rather than attempted piecemeal.

## Load/soak evidence

`tests/integration/test_runtime_lock_soak_flow.cpp` (gated behind the
`build_load_tests` Meson option, parallel to `build_live_tests`) drives real
concurrent traffic — over real TCP sockets, HTTP/1.1 keep-alive throughout —
against a running server: several users each long-polling their own room's
`/sync`, each doing ordinary authenticated reads, each sending messages into
their own room, and several simulated remote servers sending signed,
X-Matrix-authenticated inbound federation transactions, all at once. It
reports throughput and p50/p95/p99 latency per category to stderr. Its own
default duration is short enough to run safely as a CI correctness check
(nothing deadlocks or starves); a real measurement run sets
`MEROVINGIAN_LOCK_SOAK_SECONDS` to something longer:

```bash
meson configure build-wsl -Dbuild_load_tests=true
MEROVINGIAN_LOCK_SOAK_SECONDS=60 ./build-wsl/tests/merovingian-load-tests "[load-soak]"
```

See `docs/todos/production-milestone.md`, "Global runtime lock", for the
measured before/after numbers this harness produced and the resulting
narrowing decision.

**This harness is a manual tool, not a CI job — deliberately, matching the
existing `build_live_tests` precedent** (also gated behind an opt-in Meson
option with zero `.github/workflows/` wiring; see
`docs/testing-standards.md`). A real measurement run needs tens of seconds to
minutes of wall-clock time to be meaningful, which does not fit a per-PR CI
budget, and headline throughput/latency numbers on shared CI runners are
noisy and non-reproducible in a way that would make a regression gate here
more misleading than useful. Its default (unset `MEROVINGIAN_LOCK_SOAK_SECONDS`)
2-second run does stay CI-safe as a *correctness* check — nothing deadlocks
or starves — and CAN be added as a fast job later if that is wanted, but that
is a distinct decision from running it as a soak/perf gate. Use it manually,
locally or on a dedicated benchmarking host, whenever a future lock-narrowing
change needs before/after evidence.

## Fuzzing

`fuzz-http-request` exercises the request-head parser against arbitrary input. It is registered with the existing fuzz target group.
