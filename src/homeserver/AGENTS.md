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
| `media_service.cpp` | Media service entry point (delegates to `src/media/`), including remote media fetch, asynchronous uploads (`create_pending_media_upload`, `upload_pending_media`) and waits for not-yet-uploaded media (ADR-0212) |
| `media_upload_notifier.cpp` | `MediaUploadNotifier`: wakes downloads waiting for a reserved media ID's content. Leaf mutex: never waited on with `runtime.mutex` held (ADR-0212) |
| `url_preview_service.cpp` | `GET .../preview_url` (ADR-0213): the SSRF gate (`gated_fetch`: resolve, check, pin, follow redirects itself) and the preview cache. Every fetch of a client-named URL goes through it |
| `room_service.cpp` | Room operations, event persistence, signing-key lifecycle, appservice and push delivery |
| `appservice_delivery.cpp` | Application Service API outbound queue (ADR-0163): `enqueue_appservice_delivery` (request path, no network) and `drain_appservice_queues` (the one drainer thread, run by a `PeriodicJob` from `main.cpp`) |
| `deferred_pdu_retry.cpp` | Retains federation PDUs that could not yet be placed (`deferred_pdus`) and retries them: `retry_deferred_pdus`, `DeferredPduRetryJob` (R03, ADR-0165). A retry holds no lock across `ingest_pdu_event`; `ingest_pdu_event` writes rows only after signature verification |
| `redaction_service.cpp` | Applies redactions (judge, overwrite the target's stored JSON, withhold unapplied redactions from clients) and checks a local client's redaction |
| `room_power.cpp` | `may_send_state_event()`: whether a user may send a state event of a type in a room's current state, judged as the auth rules judge it (CSAZ-12) |
| `restricted_join.cpp` | `decide_restricted_join()`: as the resident, whether a user meets a restricted room's allow conditions and which local user authorises the join (R04, ADR-0185) |
| `space_hierarchy.cpp` | `GET /_matrix/client/v1/rooms/{roomId}/hierarchy` (a child room this server holds no state for is asked for over federation, see "Client requests that call another server") and the answer to `GET /_matrix/federation/v1/hierarchy/{roomId}`, judged for the authenticated requesting server; also `handle_client_room_summary` (`GET /_matrix/client/v1/room_summary/{roomIdOrAlias}`, local rooms only; a request with no token is answered before the auth gate in `client_server.cpp` and may see only a public, knock or world-readable room) |
| `default_push_ruleset.cpp` | The server-default push ruleset (`homeserver::default_push_ruleset`) |
| `stored_push_rules.cpp` | `load_user_push_rules` / `load_push_ruleset`: a user's push rules from their `m.push_rules` account data over the defaults (ADR-0204) |
| `push_room_facts.cpp` | `push_room_facts`, `room_member_display_name`, `push_evaluation_context`: the evaluation context push delivery and unread counting share |
| `push_badge_count.cpp` | `count_push_badge`: the Push Gateway `counts.unread` from one walk of the events, newest first in stream order, that stops once every room is settled, at most 10000 rows (ADR-0207) |
| `push_rule_unread_classifier.cpp` | `PushRuleUnreadClassifier`: counts unread events by the user's push rules, from the start of their current join (R15, ADR-0205) |
| `presence_service.cpp` | Presence (CS API "Presence", SS API `m.presence`): `read_presence` (GET), `apply_sync_presence` (the `/sync` `set_presence` parameter), `build_sync_presence_events` (`presence.events`), `accept_inbound_presence` (the EDU sink's presence case) and `record_presence`, the one place a presence row is stored. `presence.enabled=false` turns every entry point into a no-op. Sending the EDU stays in `client_server.cpp` (`broadcast_presence_edu`), beside the other outbound EDUs |
| `push_retry.cpp` | `attempt_push_delivery` (every push attempt: circuit breaker, rejected pushkeys, scheduling retries) and `PushRetryJob`, the one thread that sends retries (R14, ADR-0206) |
| `email_push.cpp` | Kind `"email"` pushers (ADR-0219, ADR-0220): `owned_email_pusher_address` (the pushkey must be the account's own email 3PID), `remove_email_pushers_for_address`, and `EmailPushJob`, the one thread that sends due digests through `send_due_email_notifications`. It re-reads the pusher, the 3PID, the account and the badge count under `runtime.mutex`, then sends with the mutex released |
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
6. Make `normalized_target()` in `client_server.cpp` recognise the path. A path with
   a variable component (an ID, type or key) needs a template and a row in the HTTP-3
   scenario "gives every implemented dynamic client route its own coalesced bucket"
   in `tests/unit/test_security_audit_http_3.cpp` (ADR-0092); a fixed path needs an
   entry in `static_routes` and a row in `client_static_route_allow` listing EVERY
   method it serves (a method missing there is answered `405 M_UNRECOGNIZED`
   before authentication). A path the matcher cannot place is answered
   `404 M_UNRECOGNIZED` before authentication (`client_route_is_known`, ADR-0230), so
   a route missing there is unreachable for every caller

## The runtime lock and blocking calls

`handle_client_server_request` and `handle_local_http_request` each take
`HomeserverRuntime::mutex` around request state. Inbound federation takes it
for setup and narrower runtime callbacks; its core runs outside the global
lock, and prepared database commits release it. Anything holding the mutex
still blocks other clients and federation callbacks that need runtime state.

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

`publicRooms?server=` (GET and POST), a remote room-alias lookup, a remote user's profile (`remote_profile_response`: relays only `displayname`/`avatar_url`), remote media download or
thumbnail, and the `/thirdparty/*` lookups that call an appservice (ADR-0181) make this server
call a peer it does not control, and the spec lets clients make them
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

The space hierarchy (`handle_client_space_hierarchy`) is the same kind of request: a child room not held locally is asked
for from the `via` servers of its link, so the walk takes one slot at its first such call (`RemoteHierarchy` in
`space_hierarchy.cpp`, held until the walk ends), draws every call from one `OutboundDeadline`, makes at most 16 calls and
asks at most 3 servers per room, and answers `429 M_LIMIT_EXCEEDED` when the slot is refused. A remote answer is untrusted:
only spec fields are copied, only rooms the requested space's `children_state` names are cached from `children`, local
state beats the remote answer, and a room is shown to the user only if the user may see it by the remote summary's own
`join_rule` / `world_readable` / `allowed_room_ids`.

`perform_outbound_call` (every federated join, leave, knock and proxied lookup) resolves its
destination through `runtime.cached_discovery` with `DiscoveryCachePolicy::successes_only`, never
`discover_server` directly: the two calls of one join used to repeat the whole `.well-known` cascade.
It uses the cache only while the cache wraps `runtime.discovery_network` (compared by address; a test
that swaps the network falls back to the raw network), and it must never serve a remembered failure
(a retried join after the peer recovers is not refused). Keep the lookup inside the
`RuntimeLockRelease` scope.

The caps derive from the main request pool size (`server.http.request_threads`, applied by
`start_runtime` through `client_outbound_proxy_policy_for_pool`); they have no configuration of their
own. A new
route that proxies to a remote server without one of these three is the defect. See ADR-0079 and
`docs/http-transport.md` "Client-triggered outbound proxying".

Two more requests defer to the media fetch pool the same way: a download of a reserved media ID
that waits for its upload (ADR-0212), and a URL preview (ADR-0213). A pending-upload wait is
admitted before it starts (`await_pending_upload`): under `pending_upload_waits`, at most
`media_fetch_threads - 1` at once (none with a single worker), and on a request thread with an ADR-0079 slot as well; a wait
that is not admitted answers `504 M_NOT_YET_UPLOADED` at once. Anything else that would wait on
the media fetch pool needs the same kind of cap, or it can fill the pool. A URL preview fetches a URL a
client names: it goes through `gated_fetch` in `url_preview_service.cpp`, which resolves and
checks every hop (redirects included) and pins the connection, and never through
`resolve_media_redirect_url` or a client that follows redirects itself.

Remote media is the exception (ADR-0121): the server runs it on the media fetch pool, not the main
pool. On the main pool `fetch_remote_media_live` runs in `RemoteMediaFetchMode::defer` and, after the
refusal, policy and cache checks, records a deferral instead of fetching; the transport admits the
request to `media_fetch_budget` and hands it to the pool, which runs it again in `admitted` mode
(no ADR-0079 slot, rate limiter not consulted again). Keep every check that can answer without the
network before the deferral, so a refusal or cache hit never costs a pool slot. Fetches of one remote
file are coalesced (`RemoteMediaFetchCoalescer`): never wait on the coalescer with `runtime.mutex`
held, and never take `runtime.mutex` while holding its mutex.

## One membership exchange per user and room (ADR-0252)

A federated join, knock or leave releases `runtime.mutex` for its exchange with the resident.
Before releasing it, take a `MembershipExchangeClaim` for the (room, user) pair; `join_room`,
`knock_room` and `leave_room` refuse a claimed pair with 429 `M_LIMIT_EXCEEDED` before reading
anything. A new path that changes a user's own membership over federation takes the claim, and a
new entry point that changes it checks `membership_exchange_refusal` first, or a concurrent request
is overwritten when the exchange commits.

## Remote invites: reject, accept, rescind (Complement run 10)

An invite from another server leaves this server with a `memberships` row (`invite`) and a `PersistentInvite`
record, and no room state (an invite for a room whose state is held is judged against it). Three things act
on that record, each by the inviter's server, which the spec calls a resident server ("Leaving Rooms
(Rejecting Invites)", "Joining Rooms"):

- `leave_room` rejects it with `make_leave` / `send_leave` to `invite_sender_server` (a version 12 room ID
  names no server). If that server answers `make_leave` with 403 or 404 (it left the room), no leave can be
  authored; the invite is ended as a local `leave` row and nothing is sent. Any other failure is a 502 and
  the invite stays.
- `join_room` with no `via` uses `invite_sender_server` as the candidate, with the room ID's domain behind it.
- `rescind_invite_from_inviter` (`local_http_router.cpp`) turns a `leave` PDU for the invitee, sent by a user
  of the inviter's own server, into a `leave` for rooms whose state is not held. Nobody else can withdraw an
  invite this way.

A ban leaves a local user with no membership that makes this server interested in the room, yet the unban is
a PDU about that user: `concerns_local_member_with_row` admits an `m.room.member` PDU about a local user who
has any row for the room, to the ordinary receipt checks. Do not narrow it back to joined users, or the ban
stays for ever and the invite an unban makes valid is refused.

`stripped_state_pdus` (`room_service.cpp`) is the one place that builds `invite_room_state` and
`knock_room_state`: the stored signed PDUs of the stripped-state types, without `unsigned`. The client's
`invite_state` / `knock_state` are stripped from whatever the record holds (`build_invite_state_events_array`).

## Restricted joins as the resident (R04, ADR-0184, ADR-0185)

`decide_restricted_join` (`restricted_join.cpp`) is the only place that decides whether a
non-member may join a restricted room through an allow condition, and which local user
authorises it. Three callers use it and must stay in step: the `make_join` template provider
(names `join_authorised_via_users_server` and adds that user's member event to `auth_events`,
or refuses with 400 `M_UNABLE_TO_AUTHORISE_JOIN` / `M_UNABLE_TO_GRANT_JOIN` or 403
`M_FORBIDDEN` via `MembershipEventTemplate::error_status`), the `send_join` acceptor (co-signs
with `sign_invite_event` only when the decision authorises the named user, before the auth
checks and before storing, after `without_signatures_of` drops whatever the joining server filed
under our name; refuses unsigned otherwise), and `compose_signed_event` (refuses any local join
naming a local authoriser the decision does not accept, so `PUT /state` cannot skip the check;
a join by a user already joined has the field dropped instead, ADR-0185).
An allow condition counts as verifiable only while this server is joined to the room it names:
state kept after leaving is not current. Federation workers relay `make_join` to main
(`membership_template_ingest`), since allowed rooms may live in another shard; main refuses a
frame whose user ID is malformed or local. The decision reads state under `runtime.mutex`, takes
the room version through `declared_room_version`, and is bounded by
`max_restricted_join_conditions` (32).

### A local join no local user can authorise goes through another resident (ADR-0287, ADR-0288)

When `join_room` gets `unable_to_grant` for a local user (a condition holds, no local user can
invite), it does not refuse at once. It takes the `MembershipExchangeClaim`, runs
`wait_for_in_flight_room_events` (releases `runtime.mutex`, takes and drops the room's stripe
mutex, restores it: an event being applied now may be the power-levels event that gives a local
user the power) and decides again. Still `unable_to_grant`: `join_through_other_resident` makes
the federated handshake (`perform_federated_join` with
`FederatedJoinPurpose::join_through_resident`) to at most `max_restricted_join_fallback_candidates`
(4) servers from `restricted_join_fallback_candidates` (the client's named servers first, then
other servers with joined members; never this server), offering only the room's own version. Rules:

- Only `unable_to_grant` goes remote. A user meeting no condition (403) or a condition this server
  cannot verify (`unable_to_authorise`) is refused here, so the handshake never runs for a user this
  server has not found entitled. `decide_restricted_join` stays the only place that decides.
- The room's state is already here. Never feed the answer's `state` / `auth_chain` to
  `ingest_send_join_state`: that path seeds a room the server holds nothing of and would replace
  state it holds. The answer's `event` is stored as a received PDU through `federation.pdu_sink`
  (`origin` = the resident), so the auth rules judge it against this server's own state.
- The `event` is taken only if `verify_resident_signed_join` accepts it: the reference-hash event ID
  is that of the join this server signed, it names an authorising user of another server, and
  `filter_verified_send_join_events` verifies this server's signature and the authorising server's
  (ADR-0171). Never store a join authorised by a server whose signature was not checked.
- If no candidate succeeds the client gets the original 403, not an upstream error.

## The resident sends accepted membership events on

As the resident, the `membership_acceptor` stores a `send_join`, `send_leave` or `send_knock` and then
calls `federate_accepted_membership_event` (`room_service.cpp`) with the stored copy, so every other server
with a joined member learns of it (spec, "Joining Rooms" and "Leaving Rooms"). The requesting server is
excluded, and so is this one. It runs only for an accepted event, never a rejected or soft-failed one, with
`runtime.mutex` held, and it only enqueues. It must stay in main: a federation worker has no dispatch
worker and no signing key. A new path that stores a membership event received from another server as the
resident calls it too; it shares `queue_event_to_room_servers` with `federate_local_event`, so do not build
another transaction by hand.

## Federation worker relays are untrusted input

A frame from the federation worker is input from the process most exposed to
hostile traffic, not a verified fact. Every worker-to-main relay that carries a
PDU (`pdu_ingest`, `membership_ingest`, `invite_ingest` in `worker_pool.cpp`)
re-verifies the sender server's signature with main's own
`remote_key_resolver` and rebuilds the envelope from the verified event before
anything is persisted (ADR-0071). It also verifies a restricted join's
authorising-server signature (`federation::verify_join_authorising_server_signature`,
ADR-0171), as backfill ingestion does. Do it before taking `runtime.mutex`: resolving
a key may go to the network. A new relay that carries a PDU follows the same
pattern.

Main never signs on a worker's behalf (ADR-0078). A `sign_request` frame is refused
inline by `refuse_forbidden_worker_request`, which takes no runtime and so cannot take
`runtime.mutex` or reach a crypto provider; the handler calls it before any other frame
type. Do not add a worker-to-main frame that signs caller-supplied bytes.

## Recovering a PDU whose history is missing (A8)

`backfill_missing_pdu_references` (`local_http_router.cpp`) asks the sending server for what a PDU lacks, using
only endpoints the spec requires and the origin may be asked for:

- `POST /get_missing_events`: `latest_events` is the PDU itself (the spec: the events to retrieve the previous events
  for; the origin does not return them) and `earliest_events` is this room's forward extremities, at most ten. Never
  the PDU's `prev_events` as `latest_events`, and never the events this server is missing as `earliest_events`.
- `GET /event/{eventId}` for each named event the store lacks, and for every event a `/state_ids` snapshot names.
  `GET /event_auth` is the last resort for one event whose own auth events are not stored, never the first step: a
  peer need not serve it.
- An event the origin returns from `/get_missing_events` that is over 65536 bytes, not canonical JSON or has a
  `state_key` over 255 bytes (`returned_pdu_is_well_formed`) is dropped, and the recovery ends there: the same
  history is not then fetched through `/event`, `/state_ids` or `/event_auth`.
- A fetched PDU that cannot be placed yet goes into `HeldPdus` for that one recovery (bounded, in memory only, verified
  from scratch when placed). The state is asked at `state_snapshot_targets`, the nearest `prev_event` no held PDU can
  supply, never at a prev_event that was already fetched; held PDUs are placed oldest first afterwards.
- A snapshot fetches every missing named event before it stores any, so an auth chain the origin cannot supply leaves
  nothing stored.
- `verify_and_store_backfilled_event` stores an event with resolvable but disallowed, rejected or denied `auth_events`
  as `rejected` (after-state equal to its state-before), never drops it; only an unresolvable auth event is a gap.
  Dropping it left every event that named it unplaced.

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

## Work under the runtime lock is bounded by the request

Anything done while `runtime.mutex` is held must not grow faster than linearly with input a
client, sender or remote server controls, and per-user rows that requests scan must be capped
(security audit run-1). Examples in this module:

- `parse_federation_media_multipart` runs under the lock on a body a remote server chooses. It
  refuses a boundary over 70 characters and finds delimiters with a linear scan; keep it linear
  (ADR-0176).
- `PUT /user/{userId}/account_data/{type}` refuses a new global type past
  `max_global_account_data_per_user` with `400 M_TOO_LARGE`, and always allows an update to a
  type the user already holds (ADR-0173). `PUT /user/{userId}/rooms/{roomId}/account_data/{type}`
  is written only for a room the user holds a membership row in, and refuses a new type past
  `max_room_account_data_per_room` per room the same way (ADR-0197). Server-written rows (`m.tag`,
  `m.fully_read`) go through `set_account_data` and are never refused.
- `/search` judges a room the user has left with `room_read_access_for` only when one of its
  events would be returned, so those scans stay bounded by the page (R16).
- `expire_typing` groups the typing table by room in a fixed number of passes and hands each
  affected room its new typing list; it never rescans the table per expired room (R13).
- Sliding sync classifies `room_subscriptions` through one `sync::room_access_index` per request
  (ADR-0174).
- A user's push rules are evaluated for every event they receive. `PUT /pushrules/...` refuses a new
  rule past `max_push_rules_per_user` with `400 M_TOO_LARGE` and bounds each rule (ADR-0204);
  `m.push_rules` cannot be set through the account-data API (405).
- Push delivery's badge count (`counts.unread`, `count_push_badge`) runs per recipient per event.
  It walks `store.events.in_stream_order()` newest first, stops once every joined room is settled,
  visits at most `push_badge_row_budget` (10000) rows, and saturates at `push_badge_unread_cap`
  (1000) (ADR-0207); do not replace it with a per-room or unbounded count. Its setup walks each
  table a fixed number of times (`PushBadgeCount::table_walks`), whatever the number of rooms:
  nothing per room may walk a whole table.

## A room's version comes from its create event, through one accessor (ADR-0179)

Read a stored room's version only through `stored_room_version` / `stored_room_version_policy`
(`stored_room_version.hpp`), or `declared_room_version` for a create event in hand
(`stored_create_room_version` when what is in hand is the stored create event's JSON). A create event
without `room_version` is version 1, which has no policy: refuse the room on `nullptr`, never
substitute a default. The accessor never returns an empty string (an unusable declaration is version
1 too), because several parsers replace an empty version with `"12"`. Only a room with no stored
create (unknown here) may take a caller-chosen fallback, written as `value_or(...)` at the call
site. A federated join is refused unless the verified `m.room.create` declares the make_join
version.

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
suspension gate lets the route through). A target this server does not hold is not a 404 (the spec has none): the
redaction is stored when the sender holds the room's `redact` level and is judged when the target arrives; below
that level it is 403. A target held in another room is `target_unknown` (404).

## Errcodes the status cannot name (CSAZ-9)

`error_code_for_status` maps a status to one errcode (400 is `M_UNKNOWN`). When a room operation refuses with a
specific Matrix errcode, set `OperationResult::errcode` (as `event_too_large_result()` does for `M_TOO_LARGE`);
`response_from_operation` / `response_from_room_operation` copy it into `LocalHttpResponse::errcode`, and the client
API's `error_code_for()` and `wrap()` return it. Do not encode an errcode into the reason text or a header.

## Event size limits (CSAZ-9)

`compose_signed_event` returns a `ComposeResult`. A caller that gets `ComposeFailure::too_large` answers
`event_too_large_result()` (`413 M_TOO_LARGE`, since 0.12.60; 400 before), never the 403 or 500 it uses for other failures. The limits are
checked on the signed canonical JSON, so do not add a cheaper pre-check on the request body in their place.

## Membership projection (CSAZ-6, DB-4, ADR-0126, ADR-0149)

`persist_composed_event` projects every `m.room.member` event it stores (`local_membership_projection` and
`finish_local_membership`: the `memberships` row, `LocalRoom.members`, device-list share changes, invite
metadata). A new membership path stores its event through `persist_composed_event` and does not touch those
itself; projecting twice allocates a second stream ordering and duplicates device-list changes.
A membership learned over federation (the membership acceptor, `ingest_pdu_event`) is applied to the live
roster with `apply_membership_to_roster`, the same call `finish_local_membership` ends with, so the
device-list `changed`/`left` rows follow; never edit `LocalRoom::members` for a membership change.

The `memberships` row and invite change are never written in a transaction of their own after the event: pass
a `database::MembershipProjection` to `store_event_with_state` / `prepare_store_event_with_state` (or
`store_local_event`, or `store_event_with_bookkeeping` for a federated join), so they commit with the event and its
`current_state` row. An event this server places itself commits with all of its bookkeeping (state group, mapping,
forward extremities, resulting current state) in that one transaction (ADR-0228); do not add a write after it that a
500 could leave behind. A membership change with no
event stored here (a federated leave, `/invite` for a room whose state this server holds) uses
`store_membership_projection`. Writing the row separately is how a ban became durable while the row still
said `join` (DB-4). Hydration reconciles the rows from current state before building the roster.

## Gates that stand for a state event (CSAZ-12, ADR-0127)

When a client endpoint's action is, or advertises, a state event (`/upgrade` sends `m.room.tombstone`; directory
visibility and aliases stand for `m.room.canonical_alias`), refuse it up front with `may_send_state_event()` for that
event type, before anything is created. Membership alone is not enough. Alias `PUT` validates with
`auth::room_alias_is_valid` and requires this server's domain; `DELETE` allows the alias's recorded creator.

## Typing expiry (R13, ADR-0199)

Every path that sets a typing entry to `typing: true` sets its `expires_at`: the client's
`timeout` (default `default_typing_timeout`, at most `max_typing_timeout`), or
`federation_typing_timeout` from an inbound EDU. `expire_typing_notifications` removes expired
entries, advances the room's typing stream position and sends `typing: false` for local users; it
runs on the "typing-expiry" `PeriodicJob` in `main.cpp`. A new path that adds a typing entry must
set `expires_at`, or it never expires, and call `wake_typing_expiry` so an earlier deadline than the
job's current sleep is not missed. Every read and write of `typing_users` holds `runtime.mutex`:
the federation EDU sink runs without it and takes it itself in the typing case. Every other EDU case
that reads or writes store state (receipts, presence, device lists) or reads the visible stream
position takes it the same way; `enqueue_direct_to_device_messages` takes it itself.

## Presence

Every presence row is written through `record_presence` (it stamps `observed_at_ms`, stores, tells
appservices) and every entry point checks `presence_enabled` first: a path that stores or sends presence
without that check ignores `presence.enabled=false`. Rules:

- `GET /presence/{userId}/status` answers 403 for a user the caller shares no joined room with, whether or
  not the user exists; never 404 for a missing user (account enumeration).
- A `/sync` changes presence only on a change of state (`apply_sync_presence`), and only a change is sent
  to other servers (`broadcast_presence_edu`); a sync loop must never cost a row, a stream position or an
  EDU per poll.
- `accept_inbound_presence` binds `user_id` to the sending origin, bounds the entries it looks at, and keeps
  only users who share a joined room with a local user (one pass over the memberships per EDU). A new field
  accepted from the EDU needs a bound.
- Presence in `/sync` is built by `build_sync_presence_events`, which also sends a user's presence once to
  someone who started sharing a room with them since the token, whatever its stream position: the row's own
  position is older than the token.

## Appservice delivery (R01, ADR-0163)

A request never sends to an appservice. `enqueue_appservice_delivery` writes `appservice_outbox` rows (interest decided
at event time) and calls `HomeserverRuntime::appservice_delivery_wake`; `drain_appservice_queues` is the only sender,
called from one `PeriodicJob` thread (or directly by a test), never with `runtime.mutex` held by the caller. Do not
add an "already delivered" check to the enqueue: stream orderings commit out of order across rooms, and the outbox
primary key is the only dedupe. A transaction's ID and event are written to the cursor before the send; do not
rebuild a transaction from anything but its stored event. Clear the wake hook under `runtime.mutex` before stopping
the job.

- **Every stored event is queued once, by the code that stored it.** `queue_event_for_appservices` (room_service.cpp)
  wraps `enqueue_appservice_delivery` and passes the `state_key` of a membership event as `member_event_target` (R07).
  Send, each membership transition, the third-party invite made on join, federation PDUs and `createRoom` all call it.
  The federation `/invite` handler, for a room this server is not in, stores the invite as an outlier with no
  `LocalRoom` and calls the `room_id` overload of `enqueue_appservice_delivery` with the invitee as target: no
  transaction will bring that event again, so it is the only chance an appservice has to see its user invited.
  `createRoom` collects what it stores in a `CreatedEventQueue` whose destructor queues the events, so every exit path
  queues them and the room's alias exists when interest is judged. A new path that stores a client-visible event
  must call it too.
- **A queue is capped** (`appservice.max_queued_events`, ADR-0191): the newest event is refused, counted in
  `appservice_outbox_dropped`, and the first refusal and every thousandth is logged at warning level and audited
  (`appservice.outbox.full`). Do not evict the oldest row; it may be the transaction on the cursor.
- **Ephemeral data** (`appservice_ephemeral.cpp`, ADR-0190) is in memory only: `queue_appservice_typing` (called from
  `update_room_typing_stream_id_if_changed`), `queue_appservice_receipt` and `queue_appservice_presence` (called after
  the store write, local and federated) coalesce by key into `HomeserverRuntime::appservice_ephemeral`, bounded per
  appservice. The drainer attaches up to 100 items to the next transaction and keeps them in
  `appservice_pending_ephemeral` so a retry under the same ID carries the same items. Only a freshly built transaction
  takes queued items: a retry whose first attempt carried none carries none. With no event queued it sends an
  events-free transaction whose ID comes from `next_txn_id`. Never persist it and never queue it for `url: null`.
- **Ping and the network directory** (`client_server.cpp`) act on the appservice named by the masquerade token
  (`decode_masquerade_token`), never on a path parameter alone: `POST /_matrix/client/v1/appservice/{appserviceId}/ping`
  and `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` answer `403 M_FORBIDDEN` to a token that
  is not an appservice's. The ping holds an ADR-0079 slot and releases `runtime.mutex` for the call. The directory
  entry needs a protocol the registration declares and a room the appservice is interested in; it is persisted
  (`appservice_directory`, ADR-0192).
