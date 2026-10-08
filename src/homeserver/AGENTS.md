# src/homeserver/ — Homeserver Orchestration

The top-level module that wires all services together and handles the client-server HTTP surface.
This is the largest and most complex module — read this file carefully before making changes here.

## Key files

| File | Responsibility |
|---|---|
| `client_server.cpp` | `handle_client_server_request()` — main dispatch for all `/_matrix/client/...` and `/_matrix/media/...` endpoints |
| `http_server.cpp` | Binds sockets, accepts connections, dispatches to federation or client-server handlers |
| `local_http_router.cpp` | In-process HTTP router for inter-module calls (media, auth, sync); uses pipe-delimited internal format |
| `local_services.cpp` | Wires local service instances (auth, media, sync, rooms) into the runtime |
| `runtime.cpp` | `HomeserverRuntime` — holds all live service references and runtime state; passed by reference to every handler |
| `runtime_mutex.cpp` | The recursive mutex guarding `HomeserverRuntime` (ADR-0002) |
| `request_lock.cpp` | `RequestLockScope` / `RuntimeLockRelease` — releases the runtime lock around blocking calls (see below) |
| `auth_service.cpp` | Login, session grant, token issuance and revocation, admin bootstrap (delegates primitives to `src/auth/`) |
| `media_service.cpp` | Media service entry point (delegates to `src/media/`), including remote media fetch |
| `room_service.cpp` | Room operations, event persistence, signing-key lifecycle, appservice and push delivery |
| `redaction_service.cpp` | Applies redactions (judge, overwrite the target's stored JSON, withhold unapplied redactions from clients) and checks a local client's redaction |
| `space_hierarchy.cpp` | `GET /_matrix/client/v1/rooms/{roomId}/hierarchy` |
| `default_push_ruleset.cpp` | The server-default push ruleset returned by `/pushrules/` |
| `runtime_signing_key_store.cpp` | Production `SigningKeyStore` over the persisted server signing-key rows |
| `federation_proxy.cpp` | Forwards inbound federation requests to the out-of-process federation worker over encrypted IPC; `GET /_matrix/key/v2/server` stays local |
| `federation_request_routing.cpp` | Extracts the room ID from an inbound federation request for worker shard routing |
| `worker_pool.cpp` | Federation worker shard selection (FNV-1a of the room ID) and the main-process side of worker IPC |
| `worker_supervisor.cpp` | Spawns and monitors the federation worker child; restarts it with exponential back-off |
| `worker_env.cpp` | Minimal environment allowlist for the worker child (ADR-0042) |
| `tls.cpp` | TLS connection setup, certificate loading, non-blocking read/write retry loop (ADR-0054) |
| `local_smoke_flow.cpp` | In-process register → login → room → message flow exercised by the vertical-slice integration test |

## Architecture boundaries

```
Real HTTP client
    ↓ (raw bytes + headers)
handle_client_server_request()   ← client_server.cpp
    ↓ (internal pipe format: declared_mime|sniffed_mime|scanner_clean|bytes for media)
handle_local_http_request()      ← local_http_router.cpp
    ↓
Media / Auth / Sync / Room services
```

**Never** call `handle_local_http_request()` with a real client body. The internal format
is `declared_mime|sniffed_mime|scanner_clean|bytes` — the pipe-delimited wrapper is built by
`client_server.cpp` before the call.

## Adding a new client-server endpoint

1. Add the route match in `client_server.cpp` (find the block matching the path prefix)
2. Build the response using `dispatch_resp()` or `dispatch_err()`
3. Add a conformance test in `tests/conformance/test_client_server_conformance.cpp`
4. Add a unit test in `tests/unit/test_client_server.cpp`
5. Update `docs/matrix-v1.19-client-server-api.md` with the new endpoint
6. If the path has a variable component (an ID, type or key), add its template to
   `normalized_target()` in `client_server.cpp` and a row to the HTTP-3 scenario
   "gives every implemented dynamic client route its own coalesced bucket" in
   `tests/unit/test_security_audit_http_3.cpp`. Without it the route shares the
   rate-limit fallback bucket with every unknown path (ADR-0092)

## The runtime lock and blocking calls

`handle_client_server_request` and `handle_local_http_request` each take
`HomeserverRuntime::mutex` for the whole request, and that same mutex guards
inbound federation handling. Anything holding it blocks every other client and
every inbound `/send`.

Never make a blocking network call while holding it. Wrap the call — and only
the call — in a `homeserver::RuntimeLockRelease` scope
(`merovingian/homeserver/request_lock.hpp`):

```cpp
auto const result = [&]() {
    auto const unlocked = RuntimeLockRelease{};   // runtime.mutex released here
    return runtime.outbound_client->perform(request);
}();                                          // and re-acquired here
```

Both entry points publish their guard through `homeserver::RequestLockScope`,
which is what the default-constructed form above finds. When the guard is in
hand instead — a service function that took its own — pass it:
`RuntimeLockRelease{guard}`. **Either form releases every recursion level this
thread holds**, so a self-locking service function called from a dispatcher
that already holds the mutex still frees it outright. That is not a nicety:
releasing a single level shipped as a server-wide stall three times
(`create_room` 0.12.1, `leave_room` 0.12.3, `invite_user_by_threepid` 0.12.6).

Keep every read and mutation of runtime state outside the scope. The signing
secret is copied into an owned `core::SecretBuffer` before the release (while
`runtime.mutex` is still held) and moved into `OutboundCall::secret_key`; the call
then owns the key and can sign after releasing the mutex without dangling on the
runtime buffer.

When the released region produces values the code after it consumes, return
them from an immediately-invoked lambda — or a named function, as `join_room`
does with `perform_federated_join` — rather than declaring them above the
release. The scope boundary is then the lock boundary, and nothing has to be
default-constructed and assigned in order to survive it.

See [`docs/http-transport.md`](../../docs/http-transport.md) "Request lock and
blocking network calls".

## Client requests that call another server

`publicRooms?server=` (GET and POST), a remote room-alias lookup and remote media download or
thumbnail make this server call a peer it does not control, and the spec lets clients make them
without authentication. `RuntimeLockRelease` frees the mutex, not the thread, so each holds one of
the main pool's threads for the round trip. Every such call therefore:

1. takes a slot first: `admit_client_outbound_proxy(runtime, rate_limit_client_key(...))`
   (`client_outbound_proxy.hpp`). No slot means `429 M_LIMIT_EXCEEDED` with
   `policy.retry_after_ms`, at once, before any discovery or outbound call. The slot is an RAII
   `http::InFlightBudget::Slot`; keep it until the call has ended and take it before the
   `RuntimeLockRelease` scope opens;
2. runs under one `OutboundDeadline` (10 s directory lookups via `perform_bounded_outbound_call`,
   30 s media), which discovery and every request draw from, never longer than
   `remote_timeout`;
3. for media, is checked against `security.media.remote_fetch_enabled` and `allow_remote` before
   anything else (`remote_media_refusal`): 404 `M_NOT_FOUND`, counted but not audited.

The caps derive from the main request pool size (`server.http.request_threads`, applied by
`start_runtime` through `client_outbound_proxy_policy_for_pool`); they have no configuration of their
own. A new
route that proxies to a remote server without one of these three is the defect. See ADR-0079 and
`docs/http-transport.md` "Client-triggered outbound proxying".

Remote media is the exception (ADR-0121): the server runs it on the media fetch pool, not the main
pool. On the main pool `fetch_remote_media_live` runs in `RemoteMediaFetchMode::defer` and, after the
refusal, policy and cache checks, records a deferral instead of fetching; the transport admits the
request to `media_fetch_budget` and hands it to the pool, which runs it again in `admitted` mode
(no ADR-0079 slot, rate limiter not consulted again). Keep every check that can answer without the
network before the deferral, so a refusal or cache hit never costs a pool slot. Fetches of one remote
file are coalesced (`RemoteMediaFetchCoalescer`): never wait on the coalescer with `runtime.mutex`
held, and never take `runtime.mutex` while holding its mutex.

## Federation worker relays are untrusted input

A frame from the federation worker is input from the process most exposed to
hostile traffic, not a verified fact. Every worker-to-main relay that carries a
PDU (`pdu_ingest`, `membership_ingest`, `invite_ingest` in `worker_pool.cpp`)
re-verifies the sender server's signature with main's own
`remote_key_resolver` and rebuilds the envelope from the verified event before
anything is persisted (ADR-0071). Do it before taking `runtime.mutex`: resolving
a key may go to the network. A new relay that carries a PDU follows the same
pattern.

Main never signs on a worker's behalf (ADR-0078). A `sign_request` frame is refused
inline by `refuse_forbidden_worker_request`, which takes no runtime and so cannot take
`runtime.mutex` or reach a crypto provider; the handler calls it before any other frame
type. Do not add a worker-to-main frame that signs caller-supplied bytes.

## Read paths that return room events or state

Every client-server endpoint that returns room events goes through `sync::HistoryVisibility`
(one instance per request), and every one that returns room state or the roster goes through
`sync::room_read_access_for`. The rules, and why, are in `src/sync/AGENTS.md` ("History
visibility and room read access") and ADR-0084. Checking "is the user a member" is not enough:
the user may be joined but not entitled to an old event, and a user who has left or been banned
may still read what they saw. Today these are `/messages`, `/context`, `/event`, `/search`,
`/relations`, `/threads`, `/sync`, sliding sync, `initialSync`, `/members`, `/joined_members`,
`/state` and `/state/{type}/{key}`. A new endpoint of that kind gets a conformance scenario in
`tests/conformance/test_history_visibility_conformance.cpp`. `/notifications` is the one
deliberate exception (its rows are created at delivery for a then-joined user); say so if you
add another.

## Body size limits

- **Default cap**: `rt.limits.max_body_bytes` (64 KiB) — applied at the top of the dispatch function
- **Media uploads**: bypass the default cap; use `config::parse_size_limit(rt.homeserver.config.security().media.max_upload_size)`
- The transport (`http_server.cpp`) reads a media upload body larger than its 1 MiB cap only after
  `media_upload_authentication_refusal` has accepted the head's access token (HTTP-1, HTTP-6,
  ADR-0077); an unauthenticated one gets its 401 before a byte of the body is read. A new route that
  accepts large bodies must get the same pre-body authentication, not just a larger cap.
- Any new endpoint that accepts large bodies must explicitly opt out of the default cap

## Connections and worker threads (ADR-0077)

`http_server.cpp` never lets a worker wait on a quiet connection: `HttpConnectionDispatcher` holds
every connection that is not being served and hands it to the main pool only once it is readable,
at most `max(1, pool / 4)` per client address. Code in a request round must therefore not wait for
the *next* request or for a client that has gone quiet; return the connection (`continue_keep_alive`)
and let the dispatcher wait. A connection is owned by exactly one of the dispatcher, one pool task,
one sync-pool task or one media-fetch-pool task (`std::unique_ptr<HttpConnection>`); pass it on by
moving it, never by sharing it.

## Media upload boundary

`client_server.cpp` is responsible for:
1. Matching `/_matrix/media/v3/upload` and `/_matrix/client/v1/media/upload` (with and without `?filename=...`)
2. Extracting `Content-Type` header → `declared_mime`
3. Building `declared_mime|sniffed_mime|scanner_verdict|<body>` before calling `call_local()` —
   `sniffed_mime` from `media::sniff_mime_type()`, `scanner_verdict` from
   `media::content_matches_eicar_test_signature()` (see `src/media/AGENTS.md`)
4. Mapping internal `202` (quarantined) responses to `200` toward the client with `content_uri`

## Key docs

- `docs/http-transport.md` — HTTP handling, TLS, rate limiting
- `docs/media-repository.md` — media upload/download flow
- `docs/auth-identity.md` — token validation and session flow

## Redactions (CSAZ-11)

`PUT /rooms/{roomId}/redact/{eventId}/{txnId}` builds an `m.room.redaction` and sends it through `send_event`, like
`PUT /send`; `send_event` runs `check_local_redaction` (own event, `redact` level, or server administrator over a
local user's event) before storing it, and `compose_signed_event` puts `redacts` where the room version keeps it.
`install_redaction_reconciler` makes the persistent store call `reconcile_redactions_for_event` after every event it
stores, so a new ingest path needs no extra call. It overwrites the target's JSON with the redacted form; do not add a
copy of the original content anywhere. A suspended user may redact only their own events (the handler enforces it, the
suspension gate lets the route through).
