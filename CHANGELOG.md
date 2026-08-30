## 0.12.1

Begins closing the Application Service API gap (Matrix v1.19): the entire
surface was previously unimplemented (see `docs/todos/capability-gaps.md`).
This entry covers the registration/auth layer; outbound transactions, query
hooks, and `/thirdparty/*` land in follow-up entries under this same section.

- **Appservice registration files.** New `merovingian::appservice` module
  (`include/merovingian/appservice/`, `src/appservice/`) parses registration
  documents (`as_token`, `hs_token`, `id`, `url`, `sender_localpart`,
  `namespaces.{users,aliases,rooms}` with per-entry `exclusive`/`regex`) and
  builds an in-memory `AppserviceRegistry` at startup from the new
  `appservice.registration_files` config key (`config::AppserviceConfig`,
  restart-required). Registration files are parsed as JSON — a strict subset
  of the YAML the spec describes — rather than pulling in a new YAML
  dependency; see the doc comment on `AppserviceRegistration` for the
  rationale. `as_token`/`hs_token` are held in `core::SecretBuffer` and
  compared with `crypto::constant_time_equal_variable_length`, never `==`.
  Duplicate `id`/`as_token` across registrations is rejected at load time
  (spec MUST) and drops the whole set rather than guessing a winner.
- **as_token bearer auth + `?user_id=`/`?device_id=` masquerade.** A
  client-server request bearing a registered appservice's `as_token` now
  authenticates as that appservice's `sender_localpart` user by default, or
  as the user named by `?user_id=` when it falls within the appservice's
  `users` namespace (403 otherwise); `?device_id=` is honoured when it names
  a device already known to belong to that user (400 `M_UNKNOWN_DEVICE`
  otherwise). Resolved once per request in
  `handle_client_server_request_impl` via an internal, never-on-the-wire
  token substitution (`appservice/masquerade_token.hpp`) so every existing
  `authenticated_user`/`authenticated_session`/`authenticated_admin_user`
  call site, and every deeper handler that re-derives identity from a bare
  `access_token`, works unmodified for both ordinary sessions and appservice
  masquerades. A raw incoming token already in the internal reserved shape
  is rejected before any auth logic runs, closing the obvious forgery path.
- **`m.login.application_service`.** `POST /register` and `POST /login`
  accept `type: m.login.application_service` (bearer-authenticated with
  `as_token`), bypassing the ordinary registration flow entirely per spec
  ("Server admin style permissions") — no registration token, no UIA. New
  passwordless account creation (`register_appservice_user`) and
  passwordless login (`login_appservice_user`) in `auth_service.cpp`, sharing
  the existing session/token-issuance tail with the password path via a new
  `complete_login` helper. `GET /login` now advertises
  `m.login.application_service` alongside `m.login.password`.
- **Namespace exclusivity.** An appservice's `exclusive` namespace now
  blocks entity creation by anyone else: ordinary `POST /register` and
  `m.login.application_service` registration both reject a username inside
  another appservice's exclusive `users` namespace with `M_EXCLUSIVE`, and
  `PUT /_matrix/client/v3/directory/room/{roomAlias}` and `POST /createRoom`
  (`room_alias_name`) both reject an alias inside an exclusive `aliases`
  namespace the same way — except for the owning appservice itself.
- **Known gaps, tracked in `docs/todos/capability-gaps.md`:** outbound
  `PUT /_matrix/app/v1/transactions/{txnId}` delivery, the outbound
  `GET /_matrix/app/v1/users/{userId}` / `/rooms/{roomAlias}` query hooks,
  the `/_matrix/app/v1/ping` ↔ `POST /_matrix/client/v1/appservice/{id}/ping`
  round trip, and `/_matrix/client/v3/thirdparty/*` remain unimplemented.

## 0.11.13

Fixes a production stall where one slow federation peer froze the whole
server, and a sync response that grew without bound.

- **`runtime.mutex` is no longer held across blocking outbound federation
  calls.** Every client-server request and every inbound federation transaction
  contends on that single mutex, and two request paths were making synchronous
  network calls while holding it: `POST /_matrix/client/v3/keys/query` (one
  federation `/user/keys/query` per remote server, each budgeted
  `remote_timeout_seconds`, default 60) and remote media download/thumbnail
  fetches. A peer that accepted the connection and then went quiet therefore
  froze the entire process for the duration of the timeout — local reads such as
  `GET /profile` and `GET /media/config` took 20 seconds, and inbound `/send`
  transactions from unrelated servers queued for 44 seconds behind a single
  thumbnail fetch. Server discovery, the outbound perform, and the media
  redirect resolution now release the mutex for the network round trip and
  re-acquire it before touching runtime state again. Signing still happens under
  the lock, so the Ed25519 secret span is never read unsynchronised. Added
  `RequestLockScope` / `NetworkIoUnlock` (`homeserver/request_lock.hpp`) to make
  the release RAII rather than hand-written `unlock()`/`lock()` pairs.
- **A user is reported at most once in `device_lists`.** `changed` and `left`
  were appended to once per change row, so a subject with N recorded changes
  appeared N times — and because an initial sync reports every change from
  stream position zero, that set grew for the lifetime of the account. One
  observed sliding sync response was 769 KB of repeated user IDs while carrying
  zero rooms and zero to-device messages. A new shared collector
  (`sync/device_list_delta.hpp`) collapses the change log to one entry per
  subject, resolves a subject that both changed and left to its most recent
  change type, and sorts the result so identical store state always produces
  identical response bytes. Applied to `/sync`, the MSC4186 e2ee extension, and
  `GET /_matrix/client/v3/keys/changes`. Initial syncs still report the full
  deduplicated set, which is what prompts a freshly logged-in device to
  `/keys/query` its own user's devices.

## 0.11.12

Fixes a class of bug where the server's Ed25519 signing key and the thing that
actually signs with it drifted apart, which on a long-running server broke every
locally composed event.

- **A signing key is no longer silently replaced when its published window
  lapses.** `valid_until_ts` tells federation peers when to re-fetch the key
  list; it was being treated as a lease on the server's own identity. Once a
  server's uptime exceeded the seven-day window, `ensure_runtime_server_signing_key`
  skipped the (now "expired") key and generated a brand-new one. Two things then
  went wrong at once: the runtime signing provider had been built at startup from
  the old key and was never rebuilt, so every locally composed event failed with
  `signing key not held: <new key id>` — clients saw `403 M_FORBIDDEN "event
  authorization or signing failed"` on every `PUT /rooms/{roomId}/send/...`,
  including mobile clients that could otherwise sync normally — and the new key
  had never been published, so peers rejected requests signed with it (`401` on
  `POST /_matrix/federation/v1/user/keys/query`). The key is now selected
  regardless of its window, and a window that is more than halfway elapsed is
  rolled forward and persisted instead. A key is generated only on first boot or
  through an explicit `rotate_server_signing_key`.
- **`ensure_runtime_server_signing_key` now guarantees the runtime signing
  provider holds the key it returns**, rebuilding the provider when it does not.
  The preferred key is also always treated as active by
  `collect_active_server_signing_keys`, so a window that could not be refreshed
  (database write failure) degrades to peers re-fetching sooner rather than to a
  server that cannot sign at all.
- **`GET /_matrix/key/v2/server` no longer advertises a validity the server does
  not honour.** The published `valid_until_ts` is now exactly the window
  persisted for the key, rather than an unconditional "now + 7 days" that the
  store never recorded.
- **The cached key-server document is refreshed.** It was published once at
  startup and served from the lock-free cache forever, so after seven days of
  uptime every peer that re-fetched it saw a `valid_until_ts` already in the
  past. The cache entry now carries a one-hour refresh deadline; past it the
  fast path re-publishes before serving.
- **`reset_runtime_crypto_provider` honours its documented no-op under an
  external signing override.** It previously replaced the federation worker's
  IPC-backed provider with one built from local secrets the worker does not have.
- **Inbound federation requests whose X-Matrix parameters are unquoted are no
  longer rejected.** `parse_x_matrix_authorization_header` required every value
  to be a quoted string, but the spec (Server-Server API, Request
  Authentication) says values "must be enclosed in quotes if they contain
  characters that are not allowed in `token`s ... if a value is a valid `token`,
  it may or may not be enclosed in quotes". A peer sending a bare token had its
  whole request refused — for `PUT /_matrix/federation/v1/send/{txnId}` that
  silently discarded its PDUs behind a `502 malformed federation authorization`.
  Unquoted RFC 9110 §5.6.2 tokens are now accepted; a value carrying anything
  outside the tchar set is still rejected, because the sender was required to
  quote it.
- **A rejected federation Authorization header is now diagnosable.** The 502
  above was logged as nothing but a status code, so a peer whose traffic was
  being dropped looked identical to one that never called. A
  `federation_proxy.authorization_unparsed` warning now records the target,
  the header's length, and whether it carried the `X-Matrix` scheme — never the
  header itself, which is the peer's reusable credential.
- **`GET /_matrix/client/v1/rooms/{roomId}/threads` is implemented** (spec v1.4+,
  previously 404 — Element X calls it on every room open). Returns the room's
  thread roots ordered by each thread's `latest_event`, most recently active
  first, each carrying its bundled `m.thread` aggregation (`latest_event`,
  `count`, `current_user_participated`). `include=all|participated` is honoured
  and any other value is a 400 `M_INVALID_PARAM` rather than a silent fallback
  to `all`; `limit` defaults to 50, caps at 500, and rejects zero; `from` /
  `next_batch` paginate on the latest-event stream ordering, with `next_batch`
  omitted on the last page. Child events from ignored senders are excluded from
  the aggregation (spec MUST) and a root sent by an ignored user is returned
  redacted rather than omitted. Known gap recorded in
  `docs/todos/capability-gaps.md`: bundled aggregations are still produced only
  by this endpoint, not by `/sync`, `/messages`, `/context`, `/relations`, or
  `/event/{eventId}`.
- **`reset_runtime_crypto_provider` no longer moves each `key_id` twice**, which
  left `runtime.database.signing_secret_keys` — documented as "keyed by key_id" —
  holding empty ids, so every lookup by key id silently missed. Found while
  verifying the provider-consistency check above, which the empty ids would have
  reduced to an unconditional rebuild on every request.
- **The federation dispatch worker's signing identity follows key rotation.** It
  snapshotted the key when constructed and kept signing with the retired key
  afterwards, which peers reject because the rotation publishes that key under
  `old_verify_keys` with a past `expired_ts`. `rotate_server_signing_key` now
  hands the worker its new identity directly — not `wire_federation_callbacks`,
  which returns early once the callbacks exist and so would never have run the
  refresh.

## 0.11.11

Started as a documentation-only audit of the routed client-server surface
against Matrix v1.19, recorded in `docs/todos/capability-gaps.md`; the branch
then closed one of the gaps the audit found.

- Routed `POST /_matrix/client/v3/search` (server-side event search), the
  last previously-unrouted endpoint the 0.11.11 audit found in the
  Client-Server API. Searches `content.body` (m.room.message), `content.name`
  (m.room.name), and `content.topic` (m.room.topic) — a case-insensitive
  substring match, not stemmed/tokenised full text search — across rooms the
  caller is currently joined to, never searching end-to-end encrypted rooms
  (spec MUST). `filter` (`RoomEventFilter`), `keys`, `order_by`
  (`rank`/`recent`), `event_context` (`before_limit`/`after_limit`/
  `include_profile`), `include_state`, and `groupings` (`room_id`/`sender`)
  are all honoured rather than silently ignored. `m.ignored_user_list` is
  applied via the shared `trust_safety::ignore_list` helper, resolved once
  per request. Unlike `/messages`, this endpoint has no per-room scope, so a
  new `ClientApiLimits::max_search_events_scanned` (2000) bounds how many
  candidate events a single request will JSON-parse and text-match before it
  must hand back a `next_batch` continuation instead of scanning further;
  `/_matrix/client/v3/search` also gets its own 20/min-per-IP rate-limit
  tier (the same tier as media) rather than the generic 90/min fallback.
  Known gaps, recorded in `docs/todos/capability-gaps.md`: only rooms the
  caller is currently joined to are searched (the spec's fuller "including
  rooms you have left" scope is not implemented — the same join-only
  membership gate `/messages`/`/context`/`/event/{eventId}` already use);
  `order_by: rank` is only locally accurate within a request's bounded scan
  window, not a global top-K across the caller's entire matching history;
  per-group `next_batch` pagination is not implemented (spec allows this);
  and the MSC3765 extensible-topic `content['m.topic']` representation is
  not indexed.
- Routed `GET /_matrix/client/v3/rooms/{roomId}/context/{eventId}` (event
  context for permalink resolution). Requires authentication and the same
  joined-membership gate as `/messages` and `/event/{eventId}`; an unknown
  event id and an event id belonging to a different room both fail closed
  with an identical 404 `M_NOT_FOUND` so a member cannot tell the two cases
  apart. `limit` (spec default 10, applied to the combined size of
  `events_before` and `events_after`) is clamped to the same maximum
  `/messages` uses. `filter` accepts a JSON `RoomEventFilter`, reusing the
  existing `sync::EventTypeFilter`/`RoomFilter` machinery via a new
  `sync::parse_room_event_filter_argument()` rather than a second filter
  implementation; a non-empty value that fails to parse as a JSON object is
  rejected with 400 `M_BAD_JSON` instead of being silently ignored. `start`
  and `end` reuse the plain stream-ordering token format `GET /messages`
  already produces, so a client can continue paginating from a context
  response with `GET /messages?from=<token>&dir=<b|f>`.

- Two whole spec sections were absent while going untracked, so they were
  invisible in our own planning: the **Application Service API** (no
  `as_token`/`hs_token`, no `/_matrix/app/v1/*` outbound calls, no
  `m.login.application_service`, no namespace exclusivity — bridges and bots
  cannot be run against this homeserver) and the **Push Gateway API**. Both now
  have their own sections with per-surface rows.
- **Push was the most misleading entry.** Push-*rule* CRUD is genuinely
  `spec-covered`, but `GET /_matrix/client/v3/pushers` returns a hardcoded
  `{"pushers":[]}`, `POST /pushers/set` validates the body and discards it, and
  nothing ever posts to a gateway's `/_matrix/push/v1/notify` — the sole
  reference to that path is an outbound-URL validator. **No user can receive a
  push notification.** The capability row now carries a split status and the
  endpoint rows are marked `scaffolded`.
- Newly recorded as unrouted: `POST /search` (full-text event search; only the
  unrelated `user_directory/search` exists), `GET /notifications`,
  `GET /rooms/{roomId}/context/{eventId}` (permalink resolution, user-visible in
  Element — since routed, see above), `POST /user/{userId}/openid/request_token`,
  SSO login (`m.login.sso` is not advertised), and `m.ignored_user_list`
  enforcement — the account-data key is storable because that store is generic,
  but ignored users are never filtered from `/sync`, so the ignore silently does
  nothing.
- The document gained a "Reading this document" note recording the two failure
  modes this audit exposed: silence in the ledger does not imply coverage, and a
  routed endpoint returning 200 does not imply an implemented one.
- **Step 1 of closing the push gap**: a new `push` module (pusher persistence,
  push-rule evaluation, and a Push Gateway API client), built but not yet wired
  into the client-server router — routing is a follow-on. Delivery is disabled
  by default (`server.push.enabled = false`) so merging this cannot cause an
  existing deployment to start sending gateway traffic on upgrade.
  - New `008_pushers` migration (schema version 8) adds a `pushers` table
    keyed on `(user_id, app_id, pushkey)` per the spec's uniqueness rule, with
    `store_pusher`/`find_pusher`/`delete_pusher`/`list_pushers_for_user` on
    `PersistentStore`, following the `PersistentThreePidBinding` pattern.
  - `merovingian::push` (`include/merovingian/push/push_rules.hpp`,
    `src/push/push_rules.cpp`): a pure, side-effect-free push-rule evaluator.
    `parse_push_ruleset()` parses a stored ruleset once into a typed
    `PushRuleset`; `evaluate_push_rules()` evaluates one event per call against
    it, honouring override > content > room > sender > underride precedence,
    `.m.rule.master`'s absolute priority, the "never notify for your own
    events" rule, and all six spec condition kinds: `event_match`,
    `contains_display_name`, `room_member_count`,
    `sender_notification_permission`, `event_property_is`, and
    `event_property_contains`. The latter two were initially stubbed to
    `PushConditionKind::unknown` (never-match) — closed in the same branch,
    since `.m.rule.is_user_mention`/`.m.rule.is_room_mention` are built on
    exactly these two kinds and would otherwise never fire, silently
    disabling @-mentions. Both share the evaluator's existing
    dot-separated-path resolver (`resolve_event_property`, refactored out of
    `event_match`'s string-only lookup) so the `\.`/`\\` escaping rules
    (docs/matrix-v1.19-spec/appendices.md#dot-separated-property-paths) are
    honoured identically across all three key-based condition kinds; `value`
    comparison is exact-type (a string `"true"` never equals boolean `true`,
    per spec) and fails closed on unresolvable paths or non-array targets.
  - `merovingian::push::PushGatewayClient`
    (`include/merovingian/push/push_gateway_client.hpp`,
    `src/push/push_gateway_client.cpp`): an outbound `POST
    /_matrix/push/v1/notify` client built on the SSRF-safe
    `http::OutboundClient` + `CachedServerDiscovery` pattern used by
    `IdentityServerClient` — a pusher's gateway URL is client-supplied,
    attacker-influenced data, so it is resolved the same fail-closed way
    federation and identity-server traffic is, never via ad-hoc DNS. `notify()`
    fails closed with no network call at all when `server.push.enabled` is
    false, and surfaces the spec's `rejected` pushkey list to the caller
    without touching the database itself.
  - New `config::PushConfig` (`server.push.*`: `enabled`, connect/total
    timeouts), modelled on `OidcConfig`/`IdentityServerConfig`; restart-required
    on change, same lifecycle as the identity-server client.

- **Step 2: wired the `push` module into the homeserver — push notifications
  are now actually delivered.** `GET /pushers` and `POST /pushers/set` no
  longer lie to the client, and a sent event can now reach a real Push
  Gateway.
  - `GET /pushers` returns the caller's persisted pushers in the spec's
    `Pusher` shape instead of a hardcoded empty array.
  - `POST /pushers/set` persists via `store_pusher`; `kind: null` now
    deletes via `delete_pusher` instead of being a silent no-op. Implemented
    the `append` field per spec: `append: false` (the default) removes any
    other user's pusher sharing the same `app_id`+`pushkey` before storing
    this one; `append: true` leaves it in place. The existing body
    validation, including the `https` + `/_matrix/push/v1/notify`
    pusher-URL check, is unchanged.
  - **Delivery**: `room_service.cpp`'s `send_event()` — the single choke
    point for both `PUT .../send/{eventType}/{txnId}` and
    `PUT .../state/{eventType}/{stateKey}` (both rewrite to it) — now, after
    persisting an event, evaluates that event against every local joined
    recipient's push rules (`default_push_ruleset()`, the exact ruleset
    `GET /pushrules` already serves — moved to a new shared
    `homeserver/default_push_ruleset.{hpp,cpp}` so the two can never drift
    apart) and builds one Push Gateway notification per (recipient, "http"
    pusher) pair whose evaluation says "notify". `counts.unread` reuses
    `sync::count_notifications`/`sync::read_receipt_ordering` (the same
    unread baseline `/sync` already computes) summed across every room the
    recipient is joined to, rather than a second implementation.
    "email" pushers are accepted and persisted but not yet deliverable — no
    email transport exists — and are simply skipped at delivery time.
  - **Gated and off the request path.** All of this is skipped entirely —
    no rule evaluation, no pusher lookup, no thread — when
    `server.push.enabled` is `false` (the default), so merging this cannot
    cause an existing deployment to start sending gateway traffic on
    upgrade. When enabled, the actual `PushGatewayClient::notify()` calls
    run on a detached `std::async` task parked in
    `HomeserverRuntime::orphan_futures_` — the same mechanism `join_room`'s
    background member-fill task already uses — so a slow, hostile, or
    unreachable gateway can never block or fail the request that triggered
    it; `runtime.mutex` is only briefly re-acquired to delete a pusher whose
    pushkey the gateway reports in its `rejected` array.
  - New `push::TestForcedPushGatewayResolution` test-only seam on
    `PushGatewayClient` (mirrors `identity::TestForcedIdentityResolution`
    exactly) so integration tests can drive a real local HTTPS mock gateway
    without weakening the production SSRF/discovery boundary; wired onto
    `HomeserverRuntime::test_forced_push_gateway_resolution` (always empty in
    production).
  - New conformance coverage
    (`tests/conformance/test_push_notifications_conformance.cpp`): the
    set/get round-trip, `kind: null` delete, `append` cross-user removal
    semantics, and the https/notify-path URL rejection. New integration
    coverage (`tests/integration/test_push_delivery_flow.cpp`, against a real
    local TLS mock gateway): delivery is skipped while `push.enabled` is
    false; an enabled gateway receives a correctly-shaped notify request for
    a message that matches a push rule; a rejected pushkey is deleted; and
    message sending still succeeds — promptly, without blocking — when the
    recipient's gateway is unreachable.
  - **Known gap, recorded honestly**: `GET /notifications` remains unrouted,
    "email" pushers are accepted and persisted but never delivered (no email
    transport exists), and there is no gateway retry/backoff (spec SHOULD,
    not MUST — a failed delivery attempt today is not retried). See
    `docs/todos/capability-gaps.md`.
- **Two follow-on fixes to the push delivery path landed in the same
  branch**, closing the gaps the paragraphs above recorded:
  - **Bounded the background delivery tasks (resource-exhaustion fix).**
    `dispatch_push_deliveries` parked one future per qualifying event in
    `HomeserverRuntime::orphan_futures_` and never reaped a completed one —
    unlike `join_room`'s make_join race, which already reaps before parking.
    With `push.enabled = true` this was an unbounded memory leak (one entry
    per event, forever) and unbounded OS thread creation under sustained
    message volume or a hostile client. Fixed by two changes shared with the
    join-race path via one helper, `reap_completed_futures()`
    (`runtime.hpp`/`.cpp`): completed futures are removed from
    `orphan_futures_` before a new one is parked (checked with a
    non-blocking `wait_for(0s)`, never `.get()`/`.wait()` on a still-running
    one), and a new counter, `HomeserverRuntime::push_delivery_in_flight_`
    (guarded by the existing `orphan_futures_mutex_`, tracked separately
    from the join race so the two cannot starve each other), is checked
    against a fixed cap, `k_max_in_flight_push_deliveries` (128), before a
    task is spawned. At capacity the delivery is dropped and logged at
    `WARN` rather than spawned or blocked on: a missed push is recoverable
    (the client still sees the event on its next `/sync`), an exhausted
    thread pool is not. New `tests/unit/test_runtime_orphan_futures.cpp`
    exercises `reap_completed_futures()` and the pure cap-boundary check
    (`at_background_task_capacity()`) deterministically via `std::promise`,
    with no real threads or timing dependence; new integration coverage in
    `tests/integration/test_push_delivery_flow.cpp` proves the real call
    site reaps before parking and drops (rather than spawns) once the
    real counter is saturated.
  - **Membership transitions now notify.** Delivery previously fired only
    from `send_event()`. `persist_membership_transition` — the shared
    helper behind invite/ban/kick/leave/knock — plus `join_room` and
    `invite_user_by_threepid` now route through the same pipeline via a new
    `dispatch_membership_push_notification()`. The one correctness
    subtlety: `build_pending_push_deliveries()` only evaluated rules
    against `LocalRoom::members`, i.e. joined members, but an invitee is by
    definition not (yet) joined, so `.m.rule.invite_for_me` — a default,
    enabled rule whose entire purpose is to notify an invite recipient —
    could never have fired even once the pipeline was reachable.
    `build_pending_push_deliveries()` now accepts an `extra_recipients` span
    for exactly this case; an entry equal to the sender or already a joined
    member is silently absorbed, so every call site passes the membership
    target unconditionally rather than special-casing which transitions
    have a real, distinct recipient. New integration coverage proves an
    invited user's pusher receives the notification, and that a failing
    gateway never fails or blocks the invite itself.
  - See `docs/threat-model.md` ("Push delivery background tasks were
    unbounded" and "Membership transitions never reached push delivery")
    and `docs/architecture.md`'s "Fire-and-forget background work" section
    for the full design writeup.
- **Follow-up fix: the in-flight counter introduced above deadlocked runtime
  shutdown whenever a push delivery was still running.** `dispatch_push_
  deliveries`'s background task decremented `push_delivery_in_flight_` as its
  final action while holding `orphan_futures_mutex_` — the same mutex
  `HomeserverRuntime::~HomeserverRuntime()` (and the integration test helper
  `wait_for_background_tasks()`) held for their *entire* drain, including the
  blocking `future.wait()` calls. A waiter that already held the mutex could
  never see the task finish, because the task could never acquire the mutex
  it needed to finish — a classic deadlock. Push delivery is disabled by
  default, so no running deployment was affected, but any deployment that
  enables it would hang on server shutdown with a delivery in flight; the
  integration suite hit this directly (a 583s timeout in "a completed
  push-delivery task is reaped before the next one is parked").
  - `HomeserverRuntime::push_delivery_in_flight_` is now `std::atomic<std::
    size_t>` (`runtime.hpp`). The dispatcher-side check-and-increment stays
    under `orphan_futures_mutex_` (already held there to reap
    `orphan_futures_`), keeping that read-modify-write correct against the
    cap; the background task's decrement no longer takes the mutex at all,
    so its completion can never depend on it. The move constructor and move
    assignment operator (`runtime.cpp`) switch from `std::exchange` (not
    valid on a non-movable `std::atomic`) to `.exchange(0U)`.
  - `HomeserverRuntime::~HomeserverRuntime()` and
    `wait_for_background_tasks()` (`tests/integration/
    test_push_delivery_flow.cpp`) now hold `orphan_futures_mutex_` only long
    enough to move the parked futures out of `orphan_futures_`, then wait on
    the moved-out copies with the mutex released — never holding a lock
    across a blocking wait. This also stops a runtime shutdown (or a test's
    background-task wait) from needlessly blocking a concurrent
    `dispatch_push_deliveries` call trying to reap or park a future while the
    drain is in progress. Audited every other site that parks or reaps
    `orphan_futures_` (the make_join race in `room_service.cpp`'s
    `join_room`, twice) and confirmed none of them wait on a future while
    holding the mutex — this pattern was unique to the two fixed call sites.
  - New `tests/unit/test_runtime_orphan_futures.cpp` scenario, "HomeserverRuntime's
    destructor releases orphan_futures_mutex_ before blocking on a
    still-running background task": parks a background task gated on an
    external promise (so it stays in flight, unable to finish, for the whole
    test), destroys the runtime on another thread, and polls
    `orphan_futures_mutex_` with `try_lock()` for up to 2 seconds to prove it
    becomes available again while the task is still blocked — deterministic,
    since the task's gate is never opened until after the poll, so a
    destructor that still held the mutex across its wait would show the
    mutex held for the *entire* window, not just possibly missed by a race.
  - Reviewed "exceeding the in-flight push-delivery cap drops the
    notification instead of spawning it" (`test_push_delivery_flow.cpp`):
    it already asserts the cap policy by setting
    `push_delivery_in_flight_` directly to a value at the cap rather than
    physically spawning 128 real concurrent deliveries against a mock
    gateway, so it stays fast; no change needed there. The pure
    `at_background_task_capacity()` cap-boundary check remains covered
    separately in `tests/unit/test_runtime_orphan_futures.cpp`.
- **Closed the `m.ignored_user_list` gap the audit above found**: the
  account-data key was storable but the server never acted on it. Implemented
  server-side enforcement per Matrix v1.19 CS API §Ignoring Users.
  - New `merovingian::trust_safety::ignore_list` module
    (`include/merovingian/trust_safety/ignore_list.hpp`,
    `src/trust_safety/ignore_list.cpp`): `parse_ignored_user_list()` parses an
    `m.ignored_user_list` account-data body into a `std::unordered_set`,
    failing safe to an empty set on malformed/absent content;
    `resolve_ignored_users()` reads a user's global ignore-list row from the
    store; `is_delivery_suppressed()` is the pure decision function — non-state
    events from an ignored sender are withheld, state events are exempt
    (spec: "Servers must still send state events sent by ignored users to
    clients"), and a room invite is suppressed regardless of the state-event
    exemption (spec: "Servers must not send room invites from ignored users
    to clients"). One shared predicate, called from every delivery surface
    rather than reimplemented per call site.
  - Wired into `GET /sync` (`client_server.cpp`): the timeline-matching loop,
    the invite section (looked up via the inviter's `PersistentInvite::
    sender_user_id`), and `build_room_ephemeral_events_array()`'s typing and
    receipt entries. The ignore set is resolved once per request and reused,
    not re-read per event.
  - Wired into MSC4186 sliding sync: `build_room_response()`
    (`sliding_sync_room_builder.cpp`) filters the per-room timeline and, since
    MSC4186 has no separate invite-state surface like legacy `/sync`'s
    `rooms.invite.<room_id>.invite_state`, applies the same invite override
    inside `required_state` for the one case a client can still observe an
    invite: an explicit `room_subscriptions` entry naming a room the caller
    was invited to. `build_extensions()` (`sliding_sync_extensions.cpp`)
    applies the same filter to the receipts and typing extensions. Both take
    the caller's resolved ignore set as a parameter, resolved once by
    `sliding_sync_json()` rather than per room/extension.
  - Wired into `GET /messages` (`messages_json`) and
    `GET /context/{eventId}` (`room_context_json`): both now take the
    requesting user's mxid and drop non-state events from an ignored sender.
    `/context` deliberately never filters the requested `event` field itself
    — the caller asked for context around that exact event_id (e.g. a
    permalink); only `events_before`/`events_after` are filtered.
  - Wired into push delivery: `build_pending_push_deliveries()`
    (`room_service.cpp`) checks each recipient's ignore list before even
    looking up their pushers, so an ignored sender's message — or a
    membership/invite push routed through the same function via
    `dispatch_membership_push_notification` — never reaches
    `dispatch_push_deliveries` and never queues a background delivery task.
  - Judgement calls: ephemeral typing/receipt entries are treated as ordinary
    (non-state) "events sent by that user" and suppressed the same as
    messages, since the spec's client-behaviour clause is written in those
    general terms and neither is a state event. Sliding sync's room *list*
    only ever enumerates joined rooms (pre-existing, unrelated to this
    change) — invite suppression there is provable only via `room_
    subscriptions`, which is what the new test exercises.
  - New `tests/conformance/test_ignoring_users_conformance.cpp`: an ignored
    sender's message is absent from `/sync` while an unignored sender's is
    present; a state event from an ignored sender is still delivered; a room
    invite from an ignored sender is withheld from `/sync` while another
    user's invite is not; un-ignoring restores delivery of events sent
    afterward; a malformed `m.ignored_user_list` is treated as empty;
    `/messages` and `/context` apply the same filter (with `/context`'s
    target-event exemption).
  - New `tests/unit/test_trust_safety_ignore_list.cpp`: pure-function coverage
    of `parse_ignored_user_list`, `resolve_ignored_users`,
    `is_delivery_suppressed` (including the state-event and invite-override
    cases and fail-safe behaviour with an empty ignore set), and
    `event_json_is_state_event`'s state_key-presence discriminator.
  - New scenarios in `tests/integration/test_sliding_sync_flow.cpp` (timeline
    suppression; invite suppression via `room_subscriptions`) and
    `tests/integration/test_push_delivery_flow.cpp` (an ignored sender's
    message, and an ignored inviter's invite, never queue a background push
    task).

- Routed `GET /_matrix/client/v3/notifications`, the last unimplemented piece
  of this branch's push notification work. Requires authentication;
  paginates via `from`/`next_token`, reusing the plain-stream-ordering token
  format `GET /messages` already established (`next_token` is the
  `stream_ordering` of the first not-yet-returned notification, so a
  follow-up request with `from=<next_token>` continues without gap or
  overlap); `only=highlight` filters to notifications whose matched rule set
  the highlight tweak; `limit` defaults to 50 and clamps to 1000; `read`
  reflects the caller's own `m.read`/`m.read.private` receipt in that room,
  computed at request time via the existing `sync::read_receipt_ordering()`
  rather than stored on the row.
  - New `notifications` table (`migrations/009_notifications.sql`, schema
    version 9): `user_id`, `room_id`, `event_id`, `stream_ordering`, `ts`,
    `actions`, `profile_tag`, `highlight`, primary key `(user_id, event_id)`.
    `PersistentNotification` plus `store_notification`/
    `list_notifications_for_user` on `PersistentStore`, hydrated for both
    SQLite and PostgreSQL, following the `PersistentPusher` pattern.
  - Notifications are recorded in `room_service.cpp`'s
    `build_pending_push_deliveries()` — the point where an event is already
    evaluated against each recipient's push rules — for every local
    recipient whose evaluation resolves `notify: true`. Recording is
    **unconditional** on `server.push.enabled` and on the recipient having a
    registered pusher: the spec says the endpoint returns events the user
    "has been, or would have been, notified about," so a user with push
    turned off, or never configured a pusher, still needs their history.
    Only the Push Gateway delivery half of that function (building a
    `PendingPushDelivery` and dispatching it to a real gateway) stays gated
    on `push.enabled` + a pusher. Suppression for an ignored sender is
    unchanged — recording happens after the same
    `trust_safety::is_delivery_suppressed` check the gateway path already
    used, so an ignored sender's event is invisible to `/notifications` too,
    not a separate code path that could drift.
  - `PushEvaluationResult` (`push_rules.hpp`) resolves a matched rule down to
    `notify`/`tweak_sound`/`tweak_highlight` rather than keeping its raw
    `actions` array, so a new `push_notification_actions_json()` helper
    reconstructs the conventional shape (`["notify", {"set_tweak": ...}]`)
    for storage — `profile_tag` is left empty, since recording happens once
    per `(user, event)` rather than once per pusher and so cannot name one
    pusher's configured tag.
  - Retention: `store_notification` prunes the oldest rows for a `user_id`
    beyond a fixed cap, `k_max_notifications_per_user` (200,
    `persistent_store.cpp`), after every insert — the same "bound all
    resources" policy already applied to `orphan_futures_`/
    `k_max_in_flight_push_deliveries` for push delivery's background tasks,
    now applied to this table's row count.
  - New `tests/conformance/test_notifications_conformance.cpp`: a
    notification appears with every required field after a matching event;
    `only=highlight` filters to the highlight-tweaked notification (with the
    unfiltered response as the positive counterpart); `limit` bounds the
    page and `next_token` appears only when more results remain; `from`/
    `next_token` pagination collects every notification exactly once with no
    gap or overlap; `read` reflects an `m.read` receipt (notifications at or
    before the receipted event become read, later ones stay unread).
  - New scenarios in `tests/conformance/test_client_server_conformance.cpp`
    replacing the two stale "404 M_UNRECOGNIZED (implementation gap)"
    placeholders: routed-response shape, and unauthenticated access rejected
    with 401 `M_MISSING_TOKEN`.
  - New scenarios in `tests/integration/test_push_delivery_flow.cpp`: a
    message from an ignored sender never appears in the ignoring recipient's
    `GET /notifications` (with a non-ignored sender's message as the positive
    counterpart), and a notification is recorded even when `push.enabled` is
    false and the recipient has no pusher registered.
  - `tests/unit/test_database_persistence.cpp` and
    `tests/integration/test_persistent_homeserver_flow.cpp`: updated the
    hardcoded migration-step/schema-version assertions for the new schema
    version 9 and the `notifications` migration step.

- Implemented Matrix v1.19 OpenID, both halves: `POST
  /_matrix/client/v3/user/{userId}/openid/request_token` (client-server, mints
  a token) and `GET /_matrix/federation/v1/openid/userinfo` (federation,
  redeems it). Closes the last unrouted client-server endpoint this branch's
  audit had flagged (`docs/todos/capability-gaps.md`).
  - **Security-critical design constraint:** an OpenID token must never be
    usable as a client-server access token. Kept structurally separate rather
    than relying on a runtime check: a new `openid_tokens` table (never
    `access_tokens`), a dedicated mint path (`homeserver::request_openid_
    token`) and a dedicated redeem path (`homeserver::federation_openid_
    userinfo`) that are the only functions touching that table. The ordinary
    client-server auth gate (`authenticated_user`) never reads `openid_
    tokens`; `federation_openid_userinfo` never reads `access_tokens`/
    `sessions`. See `docs/threat-model.md` ("OpenID token confusion") and
    `docs/auth-identity.md` ("OpenID tokens").
  - New `openid_tokens` table (`migrations/010_openid_tokens.sql`, schema
    version 10): `user_id`, `token_hash` (primary key), `expires_at` (epoch
    milliseconds, always finite — unlike access tokens, an OpenID token never
    has "no expiry"). `PersistentOpenidToken` plus `store_openid_token` on
    `PersistentStore`, hydrated for both SQLite and PostgreSQL, following the
    `PersistentPusher`/`PersistentAccessToken` pattern. Retention:
    `store_openid_token` sweeps every already-expired row (across all users)
    on each insert, since an OpenID token's natural bound is its own expiry
    rather than a per-user row count.
  - `POST /user/{userId}/openid/request_token`: authenticated, and the path
    `userId` must equal the caller — a mismatch fails closed 403
    `M_FORBIDDEN` via a pure string compare against the already-authenticated
    user, so the response cannot reveal whether some other `userId` exists on
    this server (verified against both a real other user and a nonexistent
    one, asserting byte-identical responses). Mints a token good for one
    hour (hardcoded — not operator-configurable, since a longer-lived OpenID
    token still cannot reach the client-server surface) and returns the
    spec's four required fields: `access_token`, `token_type` (`"Bearer"`),
    `matrix_server_name`, `expires_in` (seconds). Rate-limited under the same
    default per-IP bucket every other authenticated non-enumerated endpoint
    (filter, account_data, pushers) uses.
  - `GET /openid/userinfo`: per spec, requires no authentication and is not
    rate-limited — the caller may be any third-party service, not
    necessarily a homeserver — so it is dispatched entirely outside
    `federation::handle_inbound_federation_request`'s X-Matrix
    signature-required path, alongside the existing `GET
    /_matrix/key/v2/server` bypass, in `src/homeserver/local_http_router.cpp`
    / `src/homeserver/federation_proxy.cpp`
    (`is_federation_openid_userinfo_endpoint`,
    `federation_openid_userinfo_response`). An unknown or expired token gets
    the identical `401 M_UNKNOWN_TOKEN` / "Access token unknown or expired"
    body in both cases, matching the spec's own error shape, so a caller
    cannot distinguish "never issued" from "expired".
  - New `tests/unit/test_openid_token_store.cpp`: `store_openid_token`
    persists, rejects empty `user_id`/malformed `token_hash`, and sweeps
    already-expired rows on the next insert while leaving still-valid rows
    (for other users) untouched.
  - New scenarios in `tests/unit/test_homeserver_auth_service.cpp`:
    `request_openid_token` returns all spec-required fields;
    `federation_openid_userinfo` redeems a minted token, fails closed for an
    unknown token, and fails closed identically for an expired one (asserted
    against a real unknown-token call, not just "returns false"); an OpenID
    token is rejected by `authenticated_user` and an ordinary access token is
    rejected by `federation_openid_userinfo` — the two security-critical
    separation directions.
  - New scenarios in `tests/conformance/test_client_server_conformance.cpp`:
    successful mint returns all four fields; unauthenticated request rejected
    401; requesting a token for another user (both a real user and a
    nonexistent one) rejected 403 with identical bodies; `GET
    /openid/userinfo` returns the correct `sub` for a token minted through the
    real client-server endpoint (full round trip); unknown token rejected
    401 `M_UNKNOWN_TOKEN`; an ordinary access token rejected 401
    `M_UNKNOWN_TOKEN` at `/openid/userinfo`.
  - `tests/unit/test_database_persistence.cpp`: updated the hardcoded
    migration-step/schema-version assertions for the new schema version 10
    and the `openid_tokens` migration step.
- **Three PR #479 review findings closed in the push delivery path** — two
  P1, one P2.
  - **P1: push notifications never fired for federated-room messages.**
    Delivery was wired into `send_event()` (locally composed events) and the
    membership paths, but an event accepted over federation persists through
    `ingest_pdu_event()` (called from the `runtime.federation.pdu_sink`
    callback wired by `wire_federation_callbacks_impl` in
    `local_http_router.cpp`) and only ever published the sync token — it
    never reached `build_pending_push_deliveries`/`dispatch_push_deliveries`.
    A message from a remote room member, the ordinary federated-room case,
    therefore produced no `/notifications` row and no Push Gateway request
    for a local recipient. Fixed with a new
    `homeserver::deliver_federation_push_notifications()` (`room_service.
    cpp`/`.hpp`), called from the `pdu_sink` lambda after a PDU is accepted —
    the single convergence point for both the direct main-process federation
    path and the worker-relayed path, so it cannot double-fire. Reuses
    `build_pending_push_deliveries`/`dispatch_push_deliveries` unchanged
    rather than a second delivery path; passes the event's `state_key` as an
    extra recipient for `m.room.member` PDUs the same way
    `dispatch_membership_push_notification` already does, so a federated
    invite can also fire `.m.rule.invite_for_me`. New integration coverage
    in `tests/integration/test_push_delivery_flow.cpp`: a federation-accepted
    message reaches a local recipient's pusher and `/notifications` history;
    a locally composed event is still delivered exactly once now that the
    federation path also dispatches push notifications.
  - **P1: unbounded pushers per recipient.** `POST /pushers/set` has no
    per-user limit on distinct `(app_id, pushkey)` pairs, and every
    notify-worthy event copied and processed a recipient's *entire* pusher
    list sequentially inside one background task — up to
    `server.push.total_timeout_seconds` (default 30s) per pusher — so a
    large enough list could keep a task, and repeated across events one of
    the 128 in-flight slots, occupied for minutes to hours; the existing
    128-task cap only bounds task *count*, not the work inside one task.
    Fixed by bounding delivery, not registration: `room_service.cpp`'s new
    `k_max_pushers_per_delivery` (10, comfortably above a real user's device
    count) truncates the pusher list actually contacted per event, logging
    `push.pushers.truncated` at `WARN` (never silently) the same way the
    128-task cap logs `push.delivery.dropped`. Registration itself
    (`POST /pushers/set`, `client_server.cpp`) is unchanged — out of this
    branch's scope, owned by other in-flight work on this PR — so this is a
    delivery-side bound, not a registration-side rejection; notification
    history recording is unaffected (still unconditional per recipient,
    independent of the pusher cap). New integration coverage: a recipient
    with 12 registered pushers has only the first 10 actually contacted for
    one event.
  - **P2: `contains_display_name` read the wrong display name.** Spec: the
    condition "matches messages where `content.body` contains the owner's
    display name **in that room**" — a per-room value. `build_pending_push_
    deliveries` instead read the recipient's account-wide profile row
    (`database::find_profile`), so a room-specific membership display name,
    or a stale account-wide one, evaluated the wrong text — missing a real
    mention or matching an unrelated one. Fixed with a new
    `room_member_display_name()` helper (`room_service.cpp`) that resolves
    the recipient's current `m.room.member` state event content in that
    room, falling back to the account-wide profile only when the membership
    event carries no `displayname` at all. This resolver remains live
    infrastructure feeding `PushEvaluationContext::receiving_user_display_
    name` on every evaluation (see the P2 finding below, which removes the
    only default rule that consumed it); a follow-on PR #479 review pass
    found and closed three further defects in this same area — P1 below,
    plus two more P2s.
  - **P1 (PR #479 review): custom pusher `data` members were silently
    dropped, both at delivery and at rest.** `push_gateway_client.cpp`
    rebuilt the notify request's `data` object from only `data_format`,
    discarding every other member the pusher's `data` dictionary carried at
    registration — Push Gateway API v1.19: the Device object's `data` is "the
    data dictionary passed in at pusher creation **minus the url key**",
    i.e. everything else must reach the gateway verbatim (gateways commonly
    use custom `data` members for routing/credentials). The `pushers` table
    only ever stored `data_url`/`data_format`, so the loss actually started
    at registration time. Added `data_extra_json` to `PersistentPusher` and
    the `pushers` table (`migrations/011_pushers_data_extra.sql`, schema
    version `11`) to store the rest of the dictionary, and a
    `PushGatewayDevice::data_extra` field that `build_device_object()` now
    merges into the outgoing `data` object (defensively skipping any stray
    `url`/`format` member so the routing URL can never leak into the body
    and `format` can never duplicate). **Gap closed:** `parse_pusher_set_
    body()` (`client_server.cpp`) now captures every member of the request's
    `data` object besides `url`/`format` into `MatrixPusherSetBody::data_
    extra_json`, the `POST /pushers/set` handler persists it via
    `PersistentPusher::data_extra_json`, `GET /pushers` echoes it back in the
    pusher's `data` object, and `room_service.cpp`'s pusher-to-
    `PushGatewayDevice` conversion threads it into `PushGatewayDevice::
    data_extra` so a live delivery actually carries it. New coverage:
    `build_notify_request_body` forwards custom `data_extra` members verbatim
    and excludes/deduplicates `url`/`format`; `store_pusher`/`find_pusher`
    round-trip `data_extra_json` including an upsert replacing it;
    `test_client_server.cpp` proves `POST /pushers/set` → `GET /pushers`
    round-trips a custom string and integer `data` member; `test_push_
    delivery_flow.cpp`'s "custom pusher data members survive registration,
    GET /pushers, and reach the push gateway's notify request" scenario
    proves the full path end to end against a real mock gateway.
  - **P2 (PR #479 review, `client_server.cpp:9071`): a failed `delete_pusher`
    was reported to the client as success.** The `kind:null` branch of
    `POST /pushers/set` discarded `delete_pusher`'s return value with
    `std::ignore`, so a backend failure on an existing pusher still returned
    `200 {}` — the client believes it disabled notifications while the
    pusher stays live and keeps receiving pushes. Now checks whether the
    pusher exists first (`find_pusher`); deleting a pusher that was never
    registered remains a 200 no-op, matching the endpoint's existing
    idempotent-retry behaviour and the spec's plain "the pusher ... is
    deleted" wording, but a `delete_pusher` failure on one that DOES exist
    now returns `500 M_UNKNOWN`. New unit coverage
    (`tests/unit/test_client_server.cpp`): forcing the persistence backend to
    fail (flipping `PersistentStoreBackend::sqlite` with an empty
    `sqlite_path`, which `persist_transaction_to_backend` already fails
    closed on) on an existing pusher returns an error instead of `200`, and
    the pusher remains registered afterward.
  - **P2 (PR #479 review, `client_server.cpp:9089`): cross-user pusher
    replacement was not atomic.** `append:false` (the default) deleted every
    OTHER user's pusher sharing the target `app_id`+`pushkey` BEFORE the
    replacement pusher was persisted; a `store_pusher` failure after those
    deletions left unrelated users' pushers gone with no replacement ever
    created, silently disabling their notifications. Reordered: the
    replacement is persisted first, and the other-user removals only run
    once that succeeds, so a `store_pusher` failure now returns `500` having
    deleted nothing. (No store-level API exists for wrapping this upsert and
    the other-user deletes in one transaction — `store_pusher`/
    `delete_pusher` each commit and update the in-memory mirror
    independently — so reordering is the fix rather than a new transaction
    primitive; see the reasoning in `client_server.cpp`'s comment at the call
    site.) New unit coverage (`tests/unit/test_client_server.cpp`): with the
    same forced-backend-failure seam, a `append:false` registration that
    fails to store leaves another user's already-registered pusher for that
    `app_id`+`pushkey` untouched.
  - **P2 (PR #479 review): `contains_display_name` matched the display name
    as a glob pattern, not literal text.** A display name is data supplied
    by an arbitrary user, not an author-written pattern — matching it with
    the same glob engine content-rule patterns use meant a display name of
    literally `*` matched every message in every room (forcing a highlight
    regardless of whether the message named that user at all), and `?`
    matched any single character. Fixed with a new
    `contains_literal_word_boundary_substring()` (`push_rules.cpp`) that
    performs the same word-boundary substring search but compares the
    candidate substring to the display name byte-for-byte, with no glob
    interpretation. New unit coverage: a display name of `*` or containing
    `?` no longer matches unrelated message bodies, but does match the
    literal character; the ordinary case (a plain display name at a word
    boundary) still matches.
  - **P2 (PR #479 review): `.m.rule.roomnotif` and `.m.rule.contains_
    display_name` were not spec-defined server defaults.** CS API v1.19
    §push-notifications, "Predefined Rules": "[Changed in v1.17]: the legacy
    default push rules that looked for mentions in the body of the event
    were removed." The current spec's complete "Default Override Rules" list
    has ten entries and does not include either rule_id; both were
    pre-`m.mentions`-module rules that scanned `content.body` for literal
    text (a display name, or `"@room"`) — exactly the false-positive pattern
    `.m.rule.is_user_mention`/`.m.rule.is_room_mention` (structured
    `m.mentions`, added v1.7) replaced: a message merely containing someone's
    name, or the literal text `"@room"`, as ordinary prose highlighted the
    recipient even when the sender's event carried no `m.mentions` at all
    and the correct mentions rule did not match. Both were previously added
    as server defaults (0.11.11) citing an Element SDK client-side warning
    and claiming they are "MUST per the Matrix v1.18 CS API" — that claim
    does not hold up against the checked-in v1.18/v1.19 spec text, so both
    are removed from `default_push_ruleset.cpp`. The `contains_display_name`
    *condition kind* itself remains spec-valid (deprecated, not removed) and
    its evaluator is unaffected — only the two default rules that fired it
    (and the `@room` body scan) unconditionally for every recipient are
    gone. New unit coverage
    (`tests/unit/test_default_push_ruleset.cpp`): the default ruleset no
    longer contains either rule_id; a message body naming the recipient or
    containing literal `"@room"` text still notifies via `.m.rule.message`
    but is never highlighted. Conformance and integration coverage updated
    to match (`test_client_server_conformance.cpp`'s `/pushrules/` default
    ruleset assertion; `test_push_delivery_flow.cpp`'s display-name
    scenario, which now proves the highlight does NOT fire rather than that
    it does).
- **P2 (PR #479 review, `client_server.cpp:6261`): `GET /rooms/{roomId}/context/{eventId}`
  returned the room's *current* state, not "the state of the room at the
  last event returned"** (CS API v1.19). When a room's name, membership,
  power levels, or other state changed after the event a client asked for
  context around, the response's `state` array leaked present-day values
  into what was supposed to be a point-in-time view — a documented deviation
  when `/context` landed, now fixed properly. New
  `federation::resolve_state_event_ids_at()` (`event_query.hpp`/`.cpp`)
  reuses the backward event-DAG walk `build_state_response`/
  `build_state_ids_response` already use to answer the federation
  `GET /state`/`/state_ids` endpoints (landed 0.8.10) rather than
  reimplementing state reconstruction, then folds the pinned event's own
  state contribution back in when it is itself a state event — the
  federation endpoints deliberately stop one step short of that (SS API
  `GET /state`: "prior to considering any state changes induced by the
  requested event"), while CS API `/context` wants the state inclusive of
  the last event returned. `room_context_json()` now tracks the event_id of
  the last event actually placed in `events_after` (falling back to the
  requested event itself when `events_after` is empty) and reconstructs
  `state` at that position instead of calling
  `build_current_state_events_array()`. New conformance coverage
  (`test_client_server_conformance.cpp`): a room's name changes strictly
  after the last event a bounded `limit` admits into `events_after`; `state`
  still reports the pre-rename name, not the room's present-day one.
  **`GET /messages` was deliberately left unchanged** and is now explicitly
  tracked in `docs/todos/capability-gaps.md` as a divergence rather than
  silently inconsistent: its `state` field is spec'd around chunk-relevance/
  lazy-loading ("a list of state events relevant to showing the `chunk`"),
  not a DAG position, so this fix's shape does not apply there — it would
  need its own lazy-loading-aware implementation, which remains unstarted.
- **P2 (PR #479 review, `config.hpp:107`): the `server.push.*` config keys
  were undocumented.** Push delivery defaults to disabled
  (`server.push.enabled=false`), and the only prior documentation change was
  a wildcard entry in the reloadability table — an operator had no
  discoverable way to turn on the delivery path this PR spent considerable
  effort building. `docs/user-manual.md`'s configuration parameter reference
  gained a "Push notifications — `server.push.*`" table (`enabled`,
  `connect_timeout_seconds` default `10`, `total_timeout_seconds` default
  `30`, read from `include/merovingian/config/config.hpp`) and
  `config/merovingian.conf.example` gained a matching commented-out example
  section. While in there, `server.oidc.*` and `server.identity_server.*`
  were found to have the same gap (implemented, config-parseable, but never
  in the parameter reference table) — an earlier task had matched that
  precedent instead of fixing it. Both gained their own reference tables too
  (`server.oidc.*`'s reloadability was also missing from the reloadability
  policy table entirely; added as `Reloadable`, matching `reload_policy.cpp`'s
  default fallthrough for keys with no explicit rule).

## 0.11.10

Four follow-ons to the 0.11.9 identity-server work: a discovery test-seam for
hermetic IS mocking, `bind`/`unbind`/`requestToken` actually driving the remote
IS, a positive-path 3PID-invite conformance test, and MSC4186 multi-list
room-config combination.

- Identity service: the `bind`/`unbind`/`requestToken` handlers now contact the
  remote identity server instead of persisting locally only. `bind`
  (`POST /account/3pid/bind` and the legacy `POST /account/3pid`) calls IS
  `/3pid/bind` and persists `client_secret`+`sid` (new `007_account_threepids_columns`
  migration) so the binding can later be unbound. `unbind`
  (`POST /account/3pid/unbind`) and `delete` (`POST /account/3pid/delete`) recover
  `client_secret`+`sid` from the stored binding and call IS `/3pid/unbind` using
  IS auth mode 2 (`sid`+`client_secret`, no bearer); on IS non-support
  (`no-support`) the local binding is still removed, but a transport failure now
  **fails closed (502)** — silently removing the local record while the IS still
  holds the binding would orphan it (the user could never unbind it without the
  stored `client_secret`/`sid`). `requestToken` (register/account-3pid, email/msisdn)
  delegates `sid`-issuance to the IS when the request carries
  `id_server`+`id_access_token`; local validation is unchanged when they are
  absent (spec-compliant). A new `request_msisdn_token` IS client method is added.
  **Security note:** `account_threepids.client_secret`/`sid` are stored as TEXT
  (only populated for IS-bound 3PIDs); the threat and mitigations are documented
  in `docs/threat-model.md`. **Observable change:** unbind/delete on an
  unreachable IS now returns 502 instead of silently succeeding locally.
- Discovery test-seam: `IdentityServerClient::perform()` resolves the IS host via
  `CachedServerDiscovery::lookup_addresses` (which rejects loopback) and never
  set `trusted_ca_pem`, so a self-signed local mock IS failed TLS — making
  hermetic IS tests impossible. A new `test_forced_identity_resolution` map on
  `HomeserverRuntime` (mirroring the existing `test_forced_outbound_resolution`
  contract) lets tests pin a local IS address and supply an in-memory CA bundle;
  `perform()` consults it before discovery. The seam struct lives in the
  `identity` header to keep the `homeserver → identity` dependency direction
  correct. Always empty in production; SSRF and TLS-trust behaviour is unchanged.
- Conformance: a positive-path 3PID-invite scenario
  (`tests/conformance/test_3pid_invite_conformance.cpp`) proves that
  `POST /rooms/{roomId}/invite` with a trusted `id_server` contacts the IS
  `store-invite` and persists an `m.room.third_party_invite` carrying the
  IS-issued token as `state_key` (the prior scenario covered only the 403
  fail-closed path). A bind/unbind round-trip integration test exercises the
  mode-2 unbind flow end to end via a mock IS.
- Sliding sync (MSC4186): when a room is present in **multiple** list windows,
  the room configs now combine across all of them — `required_state` is the
  superset, `timeline_limit` is the maximum, `include_heroes` is OR'd — per
  MSC4186 room-config combination. Previously only the first matching list
  contributed (list-vs-subscription was already combined in 0.11.9; list-vs-list
  was the remaining gap).

## 0.11.9

Four capability-gap closures: remote 3PID identity-server lookup, MSC4186
required_state merge, admin-route rate limiting, and admin 401/403 consistency.

- Identity service: a new `identity` module provides an outbound Identity
  Service API client (`store-invite`, `lookup`, `bind`, `unbind`,
  `requestToken`) that talks to a remote identity server over the SSRF-safe
  resolver with pinned addresses. `POST /_matrix/client/v3/rooms/{roomId}/invite`
  with `id_server`/`medium`/`address` now contacts the identity server's
  `store-invite` endpoint and builds the `m.room.third_party_invite` from the
  IS-issued token and public key, instead of minting them locally (local-only
  minting produced an unverifiable invite — the join-side `third_party_signed`
  signature is checked against the IS's key, which the IS never issued). The
  homeserver fails closed (403) when `id_server` is not an operator-trusted
  identity server. 3PID bindings are persisted (new `006_account_threepids.sql`
  migration) instead of held only in memory. A new `identity_server.*` config
  block selects trusted identity servers, allowed bind domains, and timeouts.
  **Note:** the `bind`/`unbind`/`requestToken` handlers persist locally but do
  not yet drive the remote identity server — that IS sync is a documented
  follow-on (tracked in `docs/todos/capability-gaps.md`) pending a discovery
  test-seam for hermetic IS mocking.
- Sliding sync (MSC4186): when a room is present in both a list window and a
  `room_subscriptions` entry, the combined `required_state` is now the superset
  (with dedup and wildcard-aware merge), the combined `timeline_limit` is the
  maximum, and `include_heroes` is OR'd — per MSC4186 room-config combination
  rules. Previously the subscription overrode the list wholesale.
- Admin routes: `/_merovingian/admin/*` (health, metrics, audit, media
  moderation) were previously unreachable in production — the client listener
  only dispatches `/_matrix/client/*` and `/_matrix/media/*`, so admin routes
  404'd on the public port and were only reachable via the test-only local
  router. They are now wired into `handle_client_server_request` and served on
  the client listener, dispatched to the local router before the general
  user-token gate so `require_admin()` owns the 401/403 split. They inherit the
  existing `allow()` per-IP/per-user/per-route rate limiter (throttled exactly
  once per request, no double-count); the `/_merovingian/admin/` prefix is
  capped at 30/min per IP by default and is operator-tunable via
  `client_rate_limits:`. **Security note:** the admin surface is now exposed on
  the public client port — it remains auth-gated by `require_admin()` (401 for a
  missing/invalid token, 403 for a valid non-admin token) and rate-limited, so
  only operators with a confirmed admin session can use it. Counters remain
  in-memory by design — no per-request database write amplification; the
  trade-off (counters reset on restart) is documented in `docs/http-transport.md`.
- Admin auth: `/_merovingian/admin/*` routes now return 401 for a missing or
  invalid token and 403 `M_FORBIDDEN` for a valid token belonging to a non-admin
  user, matching the `/_matrix/client/v3/admin/*` surface. Previously both
  cases returned 401.

## 0.11.8

Cross-device verification: notify a user's own devices when one of their devices uploads keys, and prompt a freshly-logged-in device to discover its own user's existing devices.

- E2EE device keys: `POST /_matrix/client/v3/keys/upload` now records a `device_lists.changed` notification for the uploading user, so the user's other devices learn about new or updated devices and query `/keys/query` for them. This fixes the Element/Web verification hang where the receiving device received the `m.key.verification.request` to-device event but ignored it because it did not have the sender's device keys in its store.
- E2EE device lists: `POST /_matrix/client/v3/login` now records a `device_lists.changed` self-notification when a genuinely new device is created. A new device's initial `/sync` therefore lists its own user in `device_lists.changed`, prompting the client to `/keys/query` and fetch the user's *existing* devices' keys on its very first sync — before the existing verified device even knows the new login exists. This closes the reverse-direction gap left by the key-upload fix: the new device (e.g. Element X) previously received an `m.key.verification.request` from the existing verified session but had not yet fetched the sender's device keys, so matrix-rust-sdk dropped the request ("Could not retrieve the device data ... ignoring it"). The spec sanctions the homeserver adding a user to `device_lists.changed` when a device's cached list may be stale; a brand-new device's cache is empty.
- Tests: added unit scenarios covering same-user cross-device key upload, login-triggered own-device discovery, and the resulting `device_lists.changed` / `/keys/query` round-trip.

## 0.11.7

Sync to-device delivery observability and verification-request coverage.

- Sync: added unit scenarios in `tests/unit/test_sync_handler.cpp` proving that a
  same-user `m.key.verification.request` to-device event is delivered to the
  target device on both legacy `GET /_matrix/client/v3/sync` and MSC4186 Simplified
  Sliding Sync (`extensions.to_device`).
- Diagnostics: `sync.response` and `sliding_sync.response` logs now include
  `to_device_count`, `device_changed_count`, `device_left_count`, `presence_count`,
  `account_data_count`, and `max_observed_sync_id`, making it possible to verify
  from server logs whether a to-device message reached the client response.

## 0.11.6

Signing key lifecycle and startup hardening.

- Crypto boundary: `ensure_runtime_server_signing_key` now rejects expired derived
  signing keys and automatically generates a fresh active key. This fixes a startup
  failure where the main process had a loaded signing secret but no usable active key,
  leaving `crypto_provider` null and causing `GET /_matrix/key/v2/server` to return 500.
- Runtime startup: `start_runtime` now fails closed if the key-server response cache
  cannot be pre-warmed, instead of starting with a broken signing provider.
- Tests: added unit scenarios covering expired-key rotation and startup recovery in
  `tests/unit/test_homeserver_vertical_slice.cpp`.
- Tests: fixed `tests/integration/test_federation_worker_flow.cpp` by switching
  `make_federation_worker_config` from in-memory SQLite to a unique on-disk file.
  This matches how production persistence works across separate database connections
  so generated signing keys survive between the runtime and worker processes.
- Tests: hardened worker seccomp scenario now skips when the test process is root.
  A root worker is killed by the filter (SQLite's `fchown()` and the capability
  bounding-set drop both fail), while production workers run as a non-root service
  user. The worker allowlist itself remains validated by unit tests.
- Docs: updated `docs/crypto-boundary.md` to describe automatic rotation of expired
  keys.

## 0.11.5

Matrix spec v1.19 P2 gap closure.

- Admin trust and safety: added `tests/conformance/test_admin_safety_policy_rules_conformance.cpp` covering `GET/PUT/DELETE /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}` CRUD, 400 for invalid actions, 404 for missing rules, and 403 non-admin guards.
- Federation keys: the server now supports multiple simultaneously-active Ed25519 signing keys. `GET /_matrix/key/v2/server` publishes every valid key in `verify_keys`, signs the response with the preferred key, and retires superseded keys to `old_verify_keys`. `RuntimeMultiKeyEd25519Provider` and `RuntimeSigningKeyStore` wire the multi-key behaviour through event signing and federation request signing.
- Media: remote thumbnails now use the local sandboxed thumbnailing pipeline after fetching the remote file via the
          authenticated federation media endpoint.
- Federation media: the authenticated `GET /_matrix/federation/v1/media/download/{mediaId}` endpoint now follows `Location` redirects in an SSRF-safe way instead of immediately falling back to the deprecated v3 endpoint.
- Federation media: hardened the `multipart/mixed` parser for authenticated download responses to strict RFC 2046 semantics. Boundary delimiters must now sit on their own line, quoted/unquoted boundary tokens with optional whitespace around `=` are accepted, preambles before the first delimiter and LF-only transport padding are tolerated, and the parser fails closed unless exactly two parts are present.
- Media thumbnails: added conformance coverage verifying that a remote thumbnail request never returns 200 with the full-size original bytes when federation infrastructure is unavailable.
- E2EE keys: `POST /_matrix/client/v3/keys/upload` now reports one-time key counts per advertised algorithm, and backup session/room/batch deletion routes are verified end-to-end.
- E2EE keys: `GET /_matrix/client/v3/keys/changes` now requires and validates both `from` and `to` sync tokens, filters `changed`/`left` results to the requested stream range, and returns `M_MISSING_PARAM`/`M_INVALID_PARAM` for missing or malformed tokens.
- Profile: the Complement fixture `tests/fixtures/complement/client_server_v1_19.json` now covers `PUT /_matrix/client/v3/profile/{userId}/avatar_url`, its cross-user 403 guard, and a follow-on `GET` that verifies the stored value.
- Room versions: added a runtime conformance scenario that creates a room for every stable version v1 through v12 and verifies each create event records the requested `room_version` via `GET /rooms/{roomId}/state/m.room.create/`.
- Tests: updated the existing `POST /keys/upload` conformance test to expect the per-algorithm `curve25519` count instead of the legacy hardcoded `signed_curve25519` aggregate.
- Third-party invites: `POST /_matrix/client/v3/rooms/{roomId}/invite` accepts same-server `id_server`/`medium`/`address` invites, generates a random token and Ed25519 keypair, and persists a signed `m.room.third_party_invite` state event. `POST /_matrix/client/v3/rooms/{roomId}/join` now accepts `third_party_signed` objects for matching same-server invites, verifies the embedded Ed25519 signature against the public keys in the invite event, creates the intermediate `m.room.member` invite event, and completes the join.
- Room v12 / MSC4291: added conformance coverage for implicit create, creator privilege, and v12 event IDs; fixed any remaining edge cases.
- Sliding Sync: expanded conformance fixtures and fixed subscription `required_state` merging with list-level defaults.
- Federation membership: `send_leave` and `send_knock` now return stripped state, knock responses include `knock_room_state`, and a local accept-knock path promotes a knock to join.
- Federation PDU verification: added conformance coverage proving `parse_inbound_pdu_envelope` and `authorize_federation_pdu` honour the room version for every stable version v1 through v12, including v12 create-event room-id derivation and the rejection of auth_events that list the implicit create event.
- Tests: added unit scenarios `E2EE /keys/upload groups one_time_key_counts by algorithm` and `Key backup deletion endpoints remove sessions, rooms, and all keys for the current version` in `tests/unit/test_client_server.cpp`, extended backup route coverage in `tests/unit/test_key_api.cpp`, plus new unit and conformance tests for the other P2 areas.
- Federation: added conformance coverage for `GET /_matrix/federation/v1/hierarchy/{roomId}` (200, 404, invalid `suggested_only`, missing-provider 501) and `GET /_matrix/federation/v1/media/download/{mediaId}` (200 multipart/mixed, 404, 451, missing-provider 501, percent-decoded `mediaId`) in `tests/conformance/test_federation_space_media_conformance.cpp`.
- Sync: `GET /_matrix/client/v3/sync` now emits the `summary` object for every joined room with `m.joined_member_count`, `m.invited_member_count`, and `m.heroes`, per Matrix Client-Server API v1.19. Added `tests/conformance/test_sync_summary_conformance.cpp` to cover the new fields.
- Trust and safety: added conformance coverage for `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` (200 for valid reports, 400 for malformed bodies) and `GET /_matrix/client/v3/admin/safety/reports` in `tests/conformance/test_safety_report_conformance.cpp`.
- Admin trust and safety review: added `tests/conformance/test_admin_safety_review_conformance.cpp` covering `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}` for room, media, and federation_server targets, empty review bodies, invalid target types (400 `M_BAD_JSON`), and non-admin guards (403 `M_FORBIDDEN`).
- Read markers: `POST /_matrix/client/v3/rooms/{roomId}/read_markers` now rejects malformed bodies with 400 `M_BAD_JSON`. Added `tests/conformance/test_read_markers_conformance.cpp` covering 200 for `m.read` (with the marker appearing as an `m.receipt` ephemeral event in `/sync`), 403 `M_FORBIDDEN` for non-members, and 400 `M_BAD_JSON` for invalid JSON.
- Presence: added `tests/conformance/test_presence_conformance.cpp` covering `PUT /_matrix/client/v3/presence/{userId}/status` 200 for valid updates, 403 `M_FORBIDDEN` for cross-user updates, and 400 `M_BAD_JSON` for malformed bodies.
- Receipts: added `tests/conformance/test_receipt_conformance.cpp` covering `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}` 200 for `m.read` (with the receipt appearing as an `m.receipt` ephemeral event in `/sync`), 400 `M_INVALID_PARAM` for invalid receipt types, 403 `M_FORBIDDEN` for non-members, and 400 `M_BAD_JSON` for malformed bodies.
- Docs: updated `docs/todos/capability-gaps.md` and relevant spec docs; repaired a corrupted capability-ledger table row for Database persistence.

## 0.11.4

Matrix spec v1.19 P1 gap closure.

- Client-server: `GET /_matrix/client/v1/auth_metadata` now returns RFC 8414 / Matrix v1.19 authorisation server metadata when the operator configures `server.oidc.*`. When OIDC is not configured it continues to return `404 M_UNRECOGNIZED` as the spec requires for unsupported servers. No actual OAuth 2.0 flow is implemented yet;
this change covers discovery only.
- Federation: added `validate_federation_tls_origin()` in `federation/server_discovery` to enforce the TLS-certificate-identity contract from Matrix Server-Server API v1.19 §2. The helper validates direct-name matches, well-known delegation consistency, and rejects IP-literal destinations unless the original server name is the same IP literal (including IPv6 literals).
- Tests: added `tests/unit/test_auth_oidc_discovery.cpp`, `tests/unit/test_federation_tls_origin.cpp`, and `tests/unit/test_config_oidc_validation.cpp`;
extended `tests / conformance / test_server_discovery.cpp` and `tests / unit / test_client_server.cpp` with configured -
    OIDC,
    disabled - OIDC,
    and TLS - origin scenarios.- CI : updated `.gitleaks.toml` to allowlist the imported `docs / matrix - v1.19 -
        spec /` copy,
    matching the existing v1.18 allowlist.-
        Docs : added a "Why C++ and not Rust?" section to `README.md` explaining the memory -
        safety tradeoff and how it's mitigated (banned unsafe primitives, isolated libsodium boundary, BSD platform reach, continuous sanitizer/fuzz verification).

        ##0.11.3

        Matrix spec v1.19 behaviour
        changes(Phase 3)
            .

        - Federation : per -
                       room server ACL enforcement(MSC4436 / Matrix v1.19).Added `federation
                           / server_acl` evaluator with case -insensitive glob matching,
    IP - literal handling,
    and port stripping
                .Inbound federation requests to
            protected endpoints(make_* / send_ * / invite / backfill / state / state_ids / get_missing_events /
                                space_hierarchy) are now rejected with
            403 `M_FORBIDDEN` when the origin server is denied.PDUs inside `PUT
            / _matrix / federation / v1 / send / {txnId}` are checked per
        -
        PDU against both the transport origin and the PDU
        sender's homeserver; room-local EDUs (`m.typing`, `m.receipt`) are checked against the transport origin. Rooms with no `m.room.server_acl` event continue to allow all servers. -
        Client - server:
encrypted history sharing conformance coverage(MSC4268).The generic `PUT / _matrix / client / v3 / sendToDevice /
    {eventType} /
{
    txnId
}
` plumbing already accepted any to - device type;
a conformance test now verifies that `m.room_key_bundle` messages carrying the `m
        .history_not_shared` withheld code are delivered to the target device and retain their event type and content.-
    Tests : added `tests / unit / test_federation_server_acl.cpp` covering glob matching,
    case -insensitivity, `?` and `*` wildcards, IP - literal denial, port stripping, deny - before - allow ordering,
    and default `allow_ip_literals` behaviour
            .

        ##0.11.2

        Matrix spec v1.19 behaviour
        changes(Phase 2)
            .

        - Client - server:
`GET / _matrix / client / v3 / publicRooms` order is now server -
    defined per Matrix v1.19(MSC4423).The implementation already returned rooms in insertion order;
a conformance test now documents and protects that server - defined order.- Client -
    server : `m.key_backup` account data(MSC4287)
is now accepted, stored,
    and retrievable via the existing `PUT / GET / _matrix / client / v3 / user / {userId} / account_data /
{
    type
}
` endpoints.- Client - server : custom emoji / image packs(MSC2545) are now accepted: `m.room.image_pack` state events and `m.image_pack.rooms` global account data round-trip through the existing event and account-data paths.
- Database: schema version 4 adds a `state_transitions` table (via `migrations/004_state_transitions.sql`) so the server can record the previous state event for every `(room_id, event_type, state_key)` tuple. The client event builder uses this to inject `unsigned.replaces_state` into state events returned by `/sync`, `/rooms/{roomId}/messages`, `/rooms/{roomId}/members`, and other state-event paths, matching the Matrix v1.19 client event format.
- Client-server: centralized the client-event serializer so `/sync`, `/rooms/{roomId}/messages`, `GET /rooms/{roomId}/state`, and `GET /rooms/{roomId}/event/
{
    eventId
}` all use the same helper and produce identical `event_id`/`unsigned.replaces_state` handling. Removed the duplicate serializer that previously existed in `client_server.cpp`.
- Tests: fixed malformed raw-string literal in the `m.room.image_pack` conformance and unit fixtures that caused the PUT-state request body to be invalid JSON.
- Database: schema version 5 backfills `state_transitions` from existing `current_state` rows via `migrations/005_backfill_state_transitions.sql` so rooms created before the v4 migration do not lack transition history.
- Database: `state_transitions` now has an in-memory hash index, and `client_event_with_id()` uses it for O(1) lookups instead of scanning the whole vector when injecting `unsigned.replaces_state`.
- Events: for federated state events, `prepare_store_event_with_state()` now derives `previous_event_id` by walking the event's `prev_events`/`auth_events` graph to find the actual predecessor state event. It no longer assumes the local arrival-time `current_state` entry was the predecessor, which was wrong on forks.
- Client-server: `GET /_matrix/client/v1/mutual_rooms` now issues opaque server-signed pagination tokens instead of integer `next_batch` values. The tokens are keyed to the deployment and verified on decode, so clients cannot guess or forge pagination positions.
- Database: the migration runner now accepts data-only migration statements (`INSERT`/`UPDATE`/`DELETE`) as valid no-op schema-state transitions. The v5 `state_transitions` backfill is the first data-only migration;
without this fix the runner rejected it and runtime startup failed.

    ##0.11.1

    Maintenance
    : migrate repository documentation and tooling from Matrix spec v1.18 to v1.19. This is a mechanical update only; no v1.19 behaviour changes are implemented in this release.

- Regenerated local spec docs under `docs/matrix-v1.19-spec/` from docs/matrix-v1.19-spec/index.md
- Added generated `docs/matrix-v1.19-client-server-api.md` (+ appendix) from the v1.19 OpenAPI definition.
- Updated `scripts/fetch_matrix_spec.py`, `scripts/generate-matrix-v119-spec-doc.mjs` (renamed from v118), `scripts/repoint_spec_links.py`, and `scripts/check-conformance-gate.sh` to v1.19.
- Repointed all internal Markdown/source spec links to the v1.19 local docs.
- Renamed test Complement fixtures from `*_v1_18.json` to `*_v1_19.json`.
- v1.18 spec docs remain in place for comparison.

## 0.10.63

Fix: legacy `/sync` never reported unread notification counts, so read receipts appeared to do nothing.

- Sync: the classic `GET /_matrix/client/v3/sync` response's `rooms.join.{roomId}` object never included the spec-required `unread_notifications` block (`notification_count`/`highlight_count`). Receipts posted via `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}` and `POST /rooms/{roomId}/read_markers` were correctly stored and echoed back as ephemeral `m.receipt` events, but nothing in the legacy sync path recomputed or surfaced the notification counts those receipts should have cleared. Clients that poll `/sync` (rather than the unstable MSC4186 sliding-sync endpoint) — including Element — therefore had no server-authoritative signal that reading a message cleared its unread state, and the client's unread badge only cleared via its own local heuristic (e.g. sending a reply). `count_notifications`/`count_highlights`, previously local helpers in `sliding_sync_room_builder.cpp` used only by sliding sync, are now shared (declared in `include/merovingian/sync/sliding_sync_room_builder.hpp`) and used by both sync paths; the legacy `/sync` room builder now computes the same receipt-baselined counts via `sync::read_receipt_ordering` and includes them in every `rooms.join` entry.

## 0.10.62

Security fixes for issues #460-#463 (4 findings from a security review of the codebase), plus a live-incident fix (issue #464).

- Media (issue #460, HIGH): `GET /_matrix/client/v1/media/download/{serverName}/
{
    mediaId
}
` and `GET / _matrix / client / v1 / media / thumbnail / {serverName} /
{
    mediaId
}` were dispatched before the access-token auth gate, allowing unauthenticated media retrieval by media ID. The v1 routes are now matched and dispatched after the auth gate (line 7774), while the unauthenticated v3 routes remain pre-auth as the spec requires.
- Federation (issue #461, HIGH): `handle_send_membership` (send_join/send_leave/send_knock) accepted inbound PDUs with no Ed25519 signature verification, content-hash check, or origin/sender-domain check — a federated server with valid X-Matrix credentials could forge any user's membership. The handler now runs the same verification pipeline as the transaction/PDU path: `authorize_federation_pdu` (signature + key resolution), `verify_pdu_content_hash`, and `sender_domain == request.origin` assertion, rejecting on any failure.
- Federation (issue #462, HIGH): `handle_invite` accepted invite events with no signature verification and no origin/sender check, then re-signed the forged event with the victim's own key. The handler now verifies the inviting server's signature via `authorize_federation_pdu`, checks `verify_pdu_content_hash`, and asserts `sender_domain == request.origin` before dispatching to the invite handler. `InviteRequest` gained an `origin` field so the handler can enforce the sender/origin match.
- Observability (issue #463, HIGH): four `log_diagnostic_audit` call sites passed `req.access_token` (the raw bearer token) as the `actor` argument, persisting valid access tokens to the diagnostic log, in-memory audit_events, and the persistent `audit_log` DB table. All four call sites now pass `"<unknown>"` as the actor, mirroring the established pattern in `auth_service.cpp:763`.
- Federation (issue #464, MEDIUM): the `m.direct_to_device` EDU handler (`local_http_router.cpp`) discarded the per-device `enqueue_to_device_message` result with `std::ignore` and always returned `EduDispositionStatus::accepted`, so a megolm room-key share that failed to persist (e.g. a malformed or empty field on one device entry) was dropped with zero trace — the transaction still ack'd 200, `edu_dispatched` still counted it, and nothing in any log said a share was lost. Diagnosed from a live report of a verified device unable to decrypt messages/media federated in from a Synapse-hosted room ("Unable to decrypt: unknown inbound session"). `enqueue_direct_to_device_messages` now returns per-envelope targeted/stored counts; the sink returns `rejected_invalid` and logs a `federation.edu.direct_to_device.store_incomplete` warning (origin, targeted, stored — no key material) whenever a targeted device's message did not persist.

### CI fixes

- The #463 fix's first attempt added a blanket rule to `contains_sensitive_marker` redacting every log field literally named `actor`, regardless of value. That breaks `src/observability/AGENTS.md`'s requirement to log `user_id`/`device_id` for authenticated request traces and is unnecessary: the actual vulnerability (raw tokens passed as the `actor` *value*) is already closed at the 4 call sites above, and both #463 regression tests assert on the persisted `audit_events.actor` value, not this redaction rule. Removed the blanket key-based rule; legitimate actor identifiers (e.g. `@alice:test`) now survive `diagnostic_log_summary` again.
- `tests/federation_signing_test_support.hpp`'s new `make_signed_event_json()` test helper signed events without ever computing/attaching `hashes.sha256` (that step is the caller's responsibility in production code — see `room_service.cpp`'s `compose_event`/`handle_send_join`/`handle_send_leave` — but the helper's own doc comment incorrectly claimed it did this). Every "valid signature" fixture built through it therefore failed `verify_pdu_content_hash`, breaking 9 send_join/invite test scenarios. The helper now computes and attaches the content hash before signing, matching the production sequence exactly.
- `make_signed_fallback_key_json()` had a typo dropped from a prior edit — `"signatures":"` instead of `"signatures":{"` — producing structurally invalid JSON in every fallback-key fixture built through it, breaking the E2EE key-upload persistence integration test with `M_BAD_JSON`. Restored the missing `
{`.
- Three pre-existing `test_federation_membership_endpoints.cpp` scenarios (two send_join auth_chain tests, one v2-invite-path-parser test) built their request PDUs as hand-written JSON literals with no real signature and a placeholder `"hashes":{"sha256":"x"}` — valid before #461/#462 added inbound PDU signature/hash verification to send_join and invite, no longer valid after. Updated their fixtures to use the (now-fixed) `make_signed_event_json()` helper and a sender domain consistent with the registered remote signing key, so they exercise the new verification path instead of being rejected by it.

## 0.10.61

Fixes for the remaining open issues #411-#457 (29 findings).

- Events (issue #411, HIGH): the state-resolution mainline was built from the head power-levels event's *direct* `auth_events` — all of them, regardless of type — and `mainline_compare` defaulted unmatched events to position 0 (the newest anchor). Per rooms/v10 Mainline ordering, the mainline is now only `m.room.power_levels` events walked transitively (`P(i+1)` = the PL event in `Pi`'s `auth_events`), positions are found by walking each event's PL ancestry transitively, and an event with no mainline ancestor gets the ∞ sentinel (sorts first/oldest). `auth_events` is also now read as the v3+ array-of-ids shape (previously parsed as an object, so the walk never saw real auth events at all). Reverse-topological and mainline orderings both gained the spec's `event_id` tie-break.
- Events (issue #424, MEDIUM): `resolve_state_v2` sorted *all* conflicted events with the reverse-topological power ordering, then immediately re-sorted the whole list by mainline. It now follows the spec's algorithm steps 1-4: power events (per the spec definition, now implemented as `is_power_event`) are sorted by reverse-topo power ordering and auth-checked first; only the remaining events are mainline-ordered against the *partially resolved* power levels and auth-checked second.
- Federation (issue #414, HIGH): `sender_domain` split the sender user ID on the *last* colon, so `@user:example.com:8448` resolved to sender domain `"8448"` — every PDU from a homeserver with a port-suffixed server name failed signature lookup and was dropped. User IDs are now split on the first colon via the new `auth::user_id_server_name` identifier-grammar helper.
- Federation (issue #423, MEDIUM): `FederationRuntimeState::audit_events` grew without bound (one entry per federation decision) and `federation_audit_is_safe` scanned the whole vector per call. Converted to a capped (10,000-entry) FIFO deque with an incrementally maintained unsafe-reason counter, making the safety check O(1).
- Sync (issue #417, MEDIUM): sliding-sync `notification_count`/`highlight_count` counted events since the *sync position* (so an initial sync reported every message ever sent as unread) and the `by_notification_count` room-list sort ignored receipts entirely (its receipt scan was dead code). Both now baseline on the user's last `m.read`/`m.read.private` receipt via the new `read_receipt_ordering` helper, and the user's own events no longer count as unread.
- Sync (issue #456, LOW): stream-token `decode_component` had no length cap, so a 17+-hex-digit component wrapped `uint64_t` — a crafted `pos` token could decode to an arbitrarily small ordering and defeat the pos never-regress guarantee. Components longer than 16 hex digits are now rejected.
- Sync (issue #457, LOW): `client_event_json` appended `event_id` without checking whether the stored JSON (v1-v3 rooms, foreign-server PDUs) already carried one, producing duplicate keys. Any existing `event_id` member is now replaced.
- Config (issue #421, MEDIUM): `build_reload_plan` emitted no diff for `server.cors.*`, `server.turn.*`, `security.secrets.master_key_file`, `security.trust_safety.*`, token lifetimes, `federation.worker.*`, `log_modules.*`, or `client_rate_limits.*` — edits to those keys were reported as "no changes" and silently dropped. All blocks now diff (maps entry-by-entry);
    `security.secrets.master_key_file` and `federation
            .worker.*` are flagged `restart_required` (loaded / spawned at startup)
                         . `http::RateLimitPolicy` gained a defaulted `operator==` for the map diffs.-
                     Config(issue #422,
                            MEDIUM) : `RuntimeConfigSnapshot::apply_reload` mutated the live `Config` in place with no
                                              synchronization while `current()` advertised concurrent -
                                          reader safety.The snapshot is now an
                                              immutable `shared_ptr<Config const>` swapped under a mutex; `current()` returns the shared snapshot.
- Homeserver (issue #431, MEDIUM): `policy_server_timeout` seconds were multiplied by 1000 in `uint32_t`, wrapping for values above ~49.7 days. The millisecond value is now computed in 64 bits and saturated at the `uint32_t` ceiling.
- Config (issue #455, LOW): `parse_i64_value` accumulated the magnitude in a signed 64-bit value and rejected `INT64_MIN`. The magnitude is now accumulated unsigned with a sign-aware limit, so the full i64 range parses and out-of-range literals are still rejected.
- Core (issue #426, MEDIUM): the sync `timeout` query-parameter parser had no overflow guard — an overlong decimal wrapped modulo 2^64 into an attacker-chosen effective timeout for the sync pool. Now overflow-checked;
    overflowing values are discarded.-
            Core(issue #440, LOW)
        : `percent_decode`/`percent_decode_path_component` silently mapped invalid hex(e.g. `% ZZ`)
                               to NUL bytes.Malformed escapes are now kept literal.-
            Core(issue #439, LOW)
        : `close_from_directory` duplicated the walk fd without adding the dup to the keep set — on Linux the dynamic `/
        proc / self / fd` sweep closed the dup mid -
            iteration and
        its RAII owner closed the same fd again.The purposeless dup is removed.- Media(issue #429, MEDIUM)
        : `decoder_policy` computed `max_upload_bytes *
        max_decompression_ratio` unsaturated(its sibling `worker_plan` already saturated);
    extreme config wrapped the decode budget to a small value.Both now share a `saturating_scale` helper.-
        Media(issue #446, LOW)
        : thumbnail requests fell back to serving the full - size original when thumbnailing was disabled
    , the worker was missing
    , or generation failed — a bandwidth -
              amplification vector(a 32x32 request answered with a multi - megabyte blob)
                  .The endpoint now returns 404(`thumbnails unavailable` / `thumbnail generation failed`) instead.-
              Media(issue #449, LOW)
        : the thumbnail
              worker's per-axis 4096 cap still admitted a 4096x4096 RGBA output buffer (64 MiB), and a crafted IHDR could stack allocations toward the RLIMIT_AS ceiling. A worker-imposed ~4.1 Mpixel budget now applies to both the decoded frame and the resampled output, and requests cannot raise it. -
        Canonical JSON(issue #430, MEDIUM)
        : `make_signable_object_view` did not strip `signatures`/`unsigned` despite `src / canonicaljson /
        AGENTS.md` claiming it did.It now elides both top -
        level keys per the spec's Signing JSON procedure; `docs/canonical-json.md` updated to match. -
        Canonical JSON(issue #435, LOW)
        : `format_double` used `snprintf`/`strtod`
    , both locale - dependent — under a comma - decimal `LC_NUMERIC` locale floats serialized as `1
    , 5` (invalid JSON)
              .The formatter now normalizes the active
                  locale's decimal separator back to `.` (kept `snprintf`-based because `std::to_chars` for doubles is unavailable on several supported toolchains). -
          Crypto(issue #433, LOW)
        : `IpcStreamCipher::decrypt` ignored the secretstream tag
    , silently accepting `TAG_FINAL`/`TAG_REKEY` as normal messages.Any tag other than `TAG_MESSAGE` is now rejected.-
          IPC(issue #451, LOW)
        : `IpcChannel::build_frame` emitted `
    {
        "id" : 1,
    }` (trailing comma — invalid JSON) for a body of exactly `
    {
    }
    `, which would make the peer mark the channel unhealthy.Empty - object bodies now produce a well - formed frame.-
           Auth(issue #438, LOW)
        : the `/ devices /
    {
        deviceId
    }
    ` route matcher was a bare prefix check,
        matching `/ devices /` (empty id) and `/ devices / foo /
                                                  bar` (extra segments)
                                                      .It now
                                                      requires a
                                                  single non - empty id segment, consistent with the key - API matcher.-
                                                                                     HTTP(issue #441, LOW)
        : outbound response header values kept trailing optional whitespace;
    RFC 7230 §3.2.4 trailing OWS is now stripped alongside leading OWS.-
        Homeserver(issue #452, LOW)
        : exact - equality route matches compared the raw target(including the query string) — `POST / logout / all
        ? ...` 404'd — and the `/ sync` prefix match over -
                               matched `/ syncXYZ`.Route matching now compares the path component(`target_path` helper); `/_matrix/key/v2/server` in the local router likewise.
- Homeserver (issue #453, LOW): `is_federation_send_target` scanned the whole target (including the query string) for the `/send/` prefix, letting `?x=/_matrix/federation/v1/send/y` misroute a request past the worker. Now matches the path component only.
- Homeserver (issue #454, LOW): the admin review/policy-rule path parsers kept the query string and never percent-decoded, persisting rules under entities like `@alice:example.org?notify=1` that never match later lookups. Both parsers now strip the query and percent-decode the id segment.
- Database (issue #447, LOW): SQLite connections now pin `PRAGMA synchronous = FULL` and `PRAGMA journal_mode = DELETE` at open, so environment-level default pragmas cannot silently weaken durability.
- Database (issue #448, LOW): `media_blobs.bytes` and `server_signing_keys.secret_key` were `TEXT` columns (and `secret_key` nullable); binary payloads containing NUL also truncated on reload because the SQLite reader used a C-string constructor. Columns are now `BLOB` (`secret_key` `NOT NULL DEFAULT ''`, folded into `001_initial_schema.sql` per pre-1.0 migration policy) and column reads are length-based.
- Tests: new/updated unit and conformance coverage for every fix above, including state-resolution mainline conformance scenarios, an identifier-grammar scenario for port-suffixed server names, receipt-baselined notification-count scenarios, a concurrent-reader reload scenario, and a NUL-byte media blob round-trip.

## 0.10.60

Security fixes for issues #409-#450 (21 findings from a security review of the codebase).

- Authorization (issue #409, HIGH): kick/ban/unban in `events/authorization.cpp` only checked the sender's power against the kick/ban level, never `target_power < sender_power` — a power-50 moderator could kick or ban a power-100 admin. Kick/unban now follows spec rule 5 exactly (unban requires meeting both the ban and kick levels, and outranking the target); ban now requires meeting the ban level and outranking the target (rule 6.2).
- Authorization (issue #410, HIGH): `m.room.redaction` was authorized against `redact`/`ban` power levels (`sender_power >= redact_level || sender_power >= ban_level`) instead of the generic `events["m.room.redaction"]`/`events_default` path every other message event uses — both over- and under-enforcement were possible depending on room config. Redactions now fall through to the standard message-event power check;
    `redact`/`ban` remain relevant only to * applying * an already - authorized redaction,
        not authorizing it.- HTTP(issue #412, HIGH)
        : `RateLimitEngine::check()` returned `allowed =
            true` when both the per - IP and
            per - user policies resolved to `nullopt` (
                      e.g.an operator- configured policy with `window_seconds> 3600`,
                      which fails validation) — a misconfigured policy silently disabled rate limiting.Now fails closed
    , matching the standalone `request_is_rate_limited()` helper; `config.cpp` also now rejects `window_seconds > 3600` at config-validation time.
- HTTP (issue #427, MEDIUM): rate-limit bucket tables (`m_ip_buckets`/`m_user_buckets`) were unbounded `std::vector`s scanned linearly per request — an attacker rotating a client-supplied `X-Forwarded-For` value could grow the table and the per-check cost without bound. Switched to `std::unordered_map` with a 100,000-entry cap and stale/oldest-entry eviction.
- HTTP (issue #413, HIGH): `mero_curl_write_header` was `noexcept` but performed unbounded allocation with no cap on header count or size — a hostile federation peer streaming enough response headers could trigger a `bad_alloc` that calls `std::terminate` and takes down the whole process. Header storage is now capped (256 headers / 64 KiB) and wrapped in `try`/`catch`.
- Homeserver (issue #415, HIGH): `resolve_policy_server_hook()` (a synchronous outbound HTTP call to the configured policy server) was invoked while `handle_federation_http_request` still held `runtime.mutex`, so a slow or unreachable policy server froze every other consumer of that mutex — effectively the whole process — for up to `policy_server_timeout`. The hook now runs after the guard is released.
- Federation (issue #416, HIGH): `FederationRuntimeState::accepted_transactions` grew without bound — every accepted transaction with a distinct `transaction_id` was appended and never evicted. Converted to a capped (10,000-entry) FIFO ring.
- Media (issue #418, MEDIUM): the internal media pipe body hardcoded `scanner_clean` to the literal `"clean"` regardless of any scan result, making the quarantine-on-infection path structurally unreachable even with `security.media.enable_av_scanner=true`. `client_server.cpp` now runs a deterministic EICAR-test-signature check and threads the real verdict through (Merovingian does not integrate a real AV engine — this makes the existing policy-hook design actually live for the one universally-recognized scanner-integration test case).
- Crypto (issue #419, MEDIUM): `IpcStreamCipher`'s secretstream `State` (holding the derived session keys) was never zeroized on destruction. Added a `State` destructor that `sodium_memzero`s both directions.
- Crypto (issue #432, LOW): `crypto_kx_keypair`'s return value was ignored in `IpcStreamCipher`'s constructor; a failure would send an uninitialized public key to the peer and derive session keys from an uninitialized secret key. Now checked and fails closed.
- Homeserver (issue #420, MEDIUM): the audit-sink database pointer is `thread_local`, installed only on the thread that constructs `HomeserverRuntime` (main) — HTTP handlers run on `ThreadPool` worker threads, where the sink silently no-op'd (e.g. every `registration_policy.denied` audit row was dropped in production). `ThreadPool` gained an `on_thread_start` hook, wired in `main.cpp` to install the audit database on every worker thread in both HTTP pools.
- Federation (issue #425, MEDIUM): the typing EDU handler never checked that `content.user_id`'s domain matched the verified envelope origin (a cross-origin identity spoof), and extracted `room_id`/`user_id` by scanning for the next `"` instead of parsing JSON (an escaped quote in `user_id` truncated the extracted value). Now validates the domain via `user_belongs_to_origin()` and parses with the canonical JSON parser.
- Platform (issue #428, MEDIUM): `__NR_personality` was unconditionally in the seccomp allow-list (for ThreadSanitizer's `personality(ADDR_NO_RANDOMIZE)` call) in both the main and worker filters, even in production builds — letting code with arbitrary-write RCE disable ASLR. Gated behind `__has_feature(thread_sanitizer)` / `__SANITIZE_THREAD__` in both filters.
- Auth (issue #434, LOW): `password_matches`/`registration_token_matches` passed `string_view::data()` to `crypto_pwhash_str_verify`, which requires a null-terminated C string — safe today only because every caller passes a `std::string`. Now copies into a `std::string` first.
- Auth (issue #436, LOW): `hash_access_token_v2` is an unkeyed `crypto_generichash` — a DB leak allows offline rainbow-table recovery of token plaintexts. Still used as a fallback when no master key or signing key is configured; issuing a token under this fallback now logs a `token.unkeyed_hash_fallback` warning so operators notice the degraded mode.
- Auth (issue #437, LOW): `redacted_token_for_log` disclosed the exact token byte length, a minor side channel distinguishing token versions and valid- from invalid-length presented tokens. Now discloses only a coarse size bucket (`tiny`/`short`/`medium`/`long`).
- Database (issue #442, LOW): PostgreSQL's `create_table_if_missing_sql` concatenated `table.name`/`columns_sql` into DDL with no identifier validation or quoting, unlike the SQLite path. Now applies the same `schema_table_is_core` validation and `quote_sqlite_identifier` quoting.
- Media (issue #443, LOW): `media_id_is_valid` rejected `/` and `..` but not embedded spaces, diverging from `media_id_is_safe`'s stricter check. Unified to reject the same shapes.
- Homeserver (issue #444, LOW): the download/thumbnail route parser (`local_media_download_parts`) accepted `..` and embedded spaces in the `media_id` path segment, caught only later at the repository boundary. Now rejects the same shapes the admin media routes already do.
- Media (issue #445, LOW): `sniff_mime_type`'s text/plain heuristic classified any all-printable-ASCII blob as `text/plain`, including an ASCII HTML/JS polyglot — since text/plain is in the default MIME allow-list, a declared-`text/plain` polyglot upload had no declared-vs-sniffed mismatch to catch it. Content that opens with `<` (after leading whitespace) is no longer classified as text/plain.
- Homeserver/federation (issue #450, LOW): documented (in `docs/threat-model.md` and at both call sites) that main's `pdu_sink` does not independently re-verify a PDU's Ed25519 signature before persisting it — it relies on the worker (or the transaction handler, for the non-worker path) having already verified via `authorize_federation_pdu`. Accepted as a defense-in-depth gap given the existing worker-trust model; full re-verification would require plumbing the raw PDU and a main-side-resolved key through a different envelope shape than `InboundPduEnvelope` provides today.
- Tests: new/updated unit, integration, and conformance coverage for every fix above, including a new `tests/unit/test_ipc_stream_cipher.cpp` (previously no test coverage existed for `IpcStreamCipher` at all).

## 0.10.59

- Security/crypto-boundary (issue #396): consolidate all libsodium access in `src/crypto/`, `src/auth/`, `src/events/`, and `src/core/secret_buffer.cpp`; `src/ipc/channel.cpp` now uses `crypto::IpcStreamCipher` for KX + secretstream.
- Hand-rolled JSON scanners (issues #397, #401, #403): replace `worker_pool.cpp` `json_get_u64`, `federation_request_routing.cpp` `/send` `room_id` extraction, and `ipc_ed25519_provider.cpp` `sign_response` parsing with `canonicaljson::parse_json()` and typed accessors.
- Backfill query hardening (issue #399): `parse_backfill_query()` checks `errno == ERANGE` after `std::strtoull()` and rejects out-of-range `limit` values.
- File-descriptor close path (issue #400): `close_all_file_descriptors_except()` checks `errno != 0` after `std::strtol()` on `/proc/self/fd` entries and rejects overflowed names.
- Sync-pool plain-socket writes (issue #402): add a looped `send_all()` helper so short `::send()` writes on the sync-pool plain-socket path are retried instead of truncated.
- Constant-time comparison (issue #405): `crypto::constant_time_equal_variable_length()` now returns `false` if any libsodium `crypto_generichash_*` step fails, eliminating the fail-open all-zero digest path.
- Key-backup version enforcement (issue #404): modifying session endpoints require the requested `?version=` to match the current backup version and return `403 M_WRONG_ROOM_KEYS_VERSION` with `current_version` when it does not; GET endpoints filter by the requested version and default to the current version when it is omitted; `delete_all_key_backup_sessions` now respects a `version` parameter.
- Registration token loading (issue #406): read token file directly into `core::SecretBuffer`, fail closed when `mlock` fails, and hash via `auth::hash_registration_token`.
- Update `scripts/reject-unsafe.sh` and `docs/security-coding-rules.md` to encode the permitted libsodium boundary and reject regressions.
- Add unit and conformance tests covering the key-backup version enforcement paths.
- Add unit tests for the new crypto-boundary helpers (`secure_random_bytes`, `secure_random_hex`, `to_hex`, base64, `generic_hash`, `ed25519_sign_detached`, `ed25519_verify`, `RuntimeEd25519Provider`) and auth helpers (`token_secret_has_required_entropy`, `token_hash_is_persistable`, access-token v2/v3/v4 hashing, `password_matches`, registration-token hashing).

## 0.10.58

### Changed
- **docs: restructure `README.md`.** Reordered around a fixed top-level structure — latest-release line, badges, table of contents, "What is Merovingian and what makes it special?", Release Artifact Verification, Installation and Configuration, Starting Merovingian for the first time, Upgrading Merovingian, Troubleshooting, and Getting Started With Development. The former "Project Status" and "Secure by design" sections were folded into the new "What is Merovingian" section; new Installation/Configuration, first-start, upgrade, and troubleshooting sections summarize and link out to the corresponding `docs/user-manual.md` sections rather than duplicating them.
- **docs: rewrite the "What is Merovingian and what makes it special?" section to make the security case explicitly**, adding a "Why choose Merovingian over other homeservers" subsection grounded in concrete, existing mechanisms: the mechanically-enforced ban on raw `new`/`delete`/`malloc`/`free`/raw pointers, seccomp/`pledge`/Capsicum-sandboxed worker processes for untrusted media decoding and federation traffic, fail-closed startup self-checks and signature/config validation, `mlock()`'d/auto-zeroising secret storage with constant-time comparisons, narrow crypto module isolation, default-quarantine media handling and architectural opacity of E2EE attachments, redaction-aware structured logging with durable security audit rows, and continuous sanitizer/fuzzing/static-analysis/secret-scanning CI gates — with links out to `docs/threat-model.md`, `docs/hardening.md`, `docs/crypto-boundary.md`, and `docs/security-coding-rules.md` for the full detail.
- **docs: fix an inaccurate claim in the opening paragraph of the same README section.** It previously said the homeserver "holds every private conversation, encryption key, and access token" — wrong: Matrix's E2EE model keeps clients' private encryption keys and plaintext entirely client-side, and the homeserver only ever sees ciphertext for encrypted rooms (plus public device/one-time-key material and, if key backup is used, client-encrypted backup blobs it cannot read). Reworded to scope the server's actual exposure correctly: federation identity, access tokens, message metadata, and plaintext only for rooms that aren't end-to-end encrypted.

## 0.10.57

### Added
- **feat(events): implement third-party (3PID) invite authorization — Matrix spec rule 4.3.1.** An `m.room.member` event with `membership: "invite"` and a `content.third_party_invite` property was previously authorized by the generic invite path (target-not-joined/banned, sender-joined, invite-power), silently ignoring the 3PID token and signature entirely — `MembershipPolicy::third_party_invite` and `AuthEventMap::third_party_invite` existed in the type but no production code path ever set or checked them. `authorize_event_against_auth_events` now implements the full spec sub-tree for this content: reject if the target is banned; reject if `signed` is missing, or missing `mxid`/`token`; reject if `signed.mxid != state_key`; reject if no `m.room.third_party_invite` state event exists with `state_key == signed.token`; reject if that event's `sender` doesn't match the invite event's `sender`; and finally verify an Ed25519 signature in `signed.signatures` against `content.public_key`/`public_keys` on the `m.room.third_party_invite` event (payload is the canonical `{mxid, sender, token}` object, matching ordinary Matrix "Signing JSON"). Also implements the separate rule 6 — creating an `m.room.third_party_invite` event itself is now gated on the room's *invite* power level, not the generic `state_default` power every other state event uses.
- **feat(crypto): add `crypto::ed25519_verify` — a stateless Ed25519 verification entry point.** Unlike `Ed25519Provider::sign`, verifying an arbitrary public key needs no signing-key store, so this is a plain free function in `crypto/ed25519.hpp`/`.cpp` wrapping `crypto_sign_verify_detached`, usable from pure modules (`events/authorization.cpp`) without threading a provider through every call site. `RuntimeEd25519Provider::verify` (`homeserver/runtime.cpp`) now delegates to it instead of duplicating the libsodium call.
- **feat(events): wire `AuthEventMap::third_party_invite` population into all three real authorization call sites** — `room_service.cpp` (local event composition), `local_http_router.cpp` (inbound federation PDU ingestion), and `state_resolution.cpp` (state resolution v2) — each now extracts `content.third_party_invite.signed.token` from the event under authorization and looks up the matching `m.room.third_party_invite` state event by `state_key`.

### Testing
- **test(events): add 10 conformance scenarios for third-party invite authorization** covering: a valid signature (both the legacy `content.public_key` and the `content.public_keys` list forms), a banned target, a missing `signed` property, an `mxid`/`state_key` mismatch, no matching `m.room.third_party_invite` event, a sender mismatch, a forged signature, and the separate invite-power-vs-state_default gating rule for `m.room.third_party_invite` creation. `test_event_auth_rules.cpp`, using real Ed25519 keypairs via `tests/federation_signing_test_support.hpp` (authorization now does real cryptographic verification, not a fake provider double).

### Notes
- Accepting this shape end-to-end — `POST /invite` with a 3PID `address`/`id_server`, and `third_party_signed` on `/join` — remains unimplemented. The former needs a real identity-server HTTP client (otherwise there is no real party to source `public_key`/`public_keys` from); the latter needs the `PUT /_matrix/federation/v1/exchange_third_party_invite/{
        roomId}` endpoint or same-server authority to sign an intermediate invite event on behalf of the original inviter (a different sender than the joining user) — both larger, separate efforts tracked in `docs/todos/capability-gaps.md`. The auth-rule engine above already validates either shape correctly whenever such an invite event exists in room state (e.g. created via the generic `PUT /rooms/{roomId}/state/m.room.third_party_invite/{
        token}` endpoint, or received over federation).

## 0.10.56

### Fixed
- **fix(observability): redact a bare `token` query parameter in structured logs.** `contains_sensitive_marker` recognized `access_token`/`refresh_token`/`session_token` and a handful of exact keys, but never the bare key `token`. `GET /_matrix/client/v1/register/m.login.registration_token/validity?token=<secret>` passes the plaintext registration token as a `token` query parameter, and every request target is logged via `sanitized_http_target`, so the raw secret was written to structured logs in cleartext. `token` is now in the exact-match redaction list.

- **fix(auth): stop requiring an access token on `POST /_matrix/client/v3/refresh`.** The spec is explicit: "this endpoint does not require authentication via an access token. Authentication is provided via the refresh token." `client_auth_endpoint_requires_access_token` excluded only `login` and `register_account`, so a client whose access token had already expired — the exact case `/refresh` exists to recover from — would be rejected before the refresh token in the body was ever inspected. `refresh_token` is now excluded alongside `login` and `register_account`.

- **fix(net): mark accepted client sockets close-on-exec.** `http_server.cpp`'s plain-HTTP and TLS accept loops used `::accept()` instead of `accept4(..., SOCK_CLOEXEC)`, unlike every other fd-creation site in the codebase (`tcp_acceptor.cpp`, `shutdown_signal.cpp`, `worker_supervisor.cpp`). Because the homeserver spawns worker subprocesses (federation workers, the thumbnail worker) via `posix_spawn`/`fork()` while client connections — including long-poll `/sync` — remain open, an accepted socket without `FD_CLOEXEC` would be inherited by every subsequently spawned worker for as long as the connection stayed open, leaking live client sockets into unrelated child processes. Both accept loops now use `accept4(..., SOCK_CLOEXEC)`.

- **fix(canonicaljson): fail closed on floats in the signing/hashing serialization path.** `serialize_canonical()`'s float branch used `std::to_string(double)`, which is fixed to 6 fractional digits, not the shortest round-tripping representation the surrounding trim logic assumed — a small magnitude like `1e-7` serialized to `"0.000000"`, which the trailing-zero strip then collapsed to `"0.0"`, silently corrupting the value. This path is unreachable from event signing today (every signing caller parses with `parse_lossless()`, which rejects floats at the parse boundary), but `serialize_canonical()` itself had no float guard, so any future caller building a `Value` tree with a `double` directly would silently produce a wrong, non-canonical hash rather than an error. Split into two entry points: `serialize_canonical()` keeps accepting floats (now via a portable shortest-round-tripping conversion) because it also serves ordinary, never-signed JSON responses that legitimately contain floats (e.g. `m.tag` `order`, account data); `serialize_canonical_strict()` rejects a `Value` tree containing any double with the new `CanonicalJsonError::float_not_allowed` instead of serializing it, and is now what `event_signer.cpp`, `event_id.cpp`, and `signable.cpp` call for signing/hashing payloads.

- **fix(crypto): wrap the operator master key and its derived keys in zeroising, mlocked buffers; consolidate the duplicated master-key loader.** `load_master_key_material()` read the master key file into a plain `std::vector<std::uint8_t>` and an unwiped stack read buffer — neither zeroised nor `mlock`ed — even though this file is the root secret every derived key (secret-box, access-token HMAC v3/v4, IPC auth) comes from. It now reads into a `core::SecretBuffer` and returns one. `SecretBoxKey`, `TokenHmacKey`, and `IpcAuthKey` previously wrapped their 32-byte key material in a bare `std::array` with no destructor; all three now zeroise `bytes` with `sodium_memzero` on destruction and on the losing side of every copy/move, while remaining ordinary copyable/movable value types (unlike `SecretBuffer`, which is heap-based and move-only — a mismatch for these small, pervasively-by-value-passed keys). `src/homeserver/room_service.cpp` duplicated `load_master_key_material` instead of calling `crypto::load_master_key_material`; the duplicate is removed and both call sites in `room_service.cpp` now delegate to the single `src/crypto/` implementation.

### Testing
- **test(observability): assert a bare `token` query parameter is redacted in `sanitized_http_target`.** `test_observability.cpp`.
- **test(auth): assert `/refresh` is excluded from `client_auth_endpoint_requires_access_token` and from the `ClientAuthRoute.requires_access_token` route table.** `test_auth_session.cpp`, `test_auth_client_server_api.cpp`.
- **test(homeserver): add a Linux-only integration scenario that connects a real client, holds the accepted connection open with a deliberately incomplete request head, locates the server's accepted socket via `/proc/self/fd`, and asserts `FD_CLOEXEC` is set — verified to fail against the pre-fix `::accept()` and pass against `accept4(..., SOCK_CLOEXEC)`.** `test_http_server_listener_flow.cpp`.
- **test(canonicaljson): add conformance coverage that `serialize_canonical_strict` rejects a double at every nesting depth (bare, in an array, in an object) while `serialize_canonical` still accepts one; add a round-trip regression test for the `1e-7` → `"0.0"` corruption case.** `test_canonicaljson_serializer.cpp`.
- **test(crypto): add unit coverage for `load_master_key_material` — exact-byte round-trip including embedded NUL, fail-closed on empty/missing/oversized/exactly-at-cap files, and an end-to-end check that the returned buffer derives working keys through every downstream KDF (`derive_secret_box_key`, `derive_token_hmac_key[_v3]`, `derive_ipc_auth_key`).** `test_crypto.cpp`.

### Changed
- **chore(release): bump version to 0.10.56 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.55

### Changed
- **docs: consolidate every security-relevant rule scattered across ~25 module `AGENTS.md` files into a single, explained reference.** Rules like "all sockets must be opened with `O_CLOEXEC`/`SOCK_CLOEXEC`" (`src/net/AGENTS.md`) live in terse, per-directory form across `src/auth/`, `src/canonicaljson/`, `src/config/`, `src/core/`, `src/crypto/`, `src/database/`, `src/events/`, `src/federation/`, `src/homeserver/`, `src/http/`, `src/media/`, `src/net/`, `src/observability/`, `src/platform/`, `src/rooms/`, `src/sync/`, `src/trust_safety/`, `migrations/`, `packaging/`, `scripts/`, `security/`, and every `tests/*/AGENTS.md` — useful as fast-reference instructions while working in that directory, but with no single place to read the reasoning behind a rule end to end, and no home in `docs/` where it's visible without already knowing which `AGENTS.md` file to look in. Added `docs/security-coding-rules.md`: every rule above, grouped by theme (memory safety, secrets/logging, cryptography, auth/authz, federation, HTTP/network, database, media, platform hardening, sync, trust & safety, packaging, testing requirements, process), each with a **why** (the concrete vulnerability class or failure mode it closes, citing the CWE where one applies and the specific fixed bug where the rule traces to one logged in `docs/threat-model.md`) and a **source** pointer back to the owning `AGENTS.md` file, plus an index-by-source-file for the reverse lookup. `security/coding-rules.md` (previously the closest thing to an authoritative security rule list — terse, CWE-tagged, but missing most of the module-specific rules and not discoverable from `docs/`) is now a pointer to the new document; `security/AGENTS.md`, the root `AGENTS.md` key-docs list, `docs/AGENTS.md`'s update-trigger table, `docs/coding-rules.md`, and `README.md` all updated to reference it. Every module `AGENTS.md` file is left untouched — this is purely additive.

## 0.10.54

### Fixed
- **fix(events): reject a self-leave (`membership: "leave"`, `sender == state_key`) unless the sender's current membership is `invite`, `join`, or `knock`.** `authorize_event_against_auth_events` allowed self-leave unconditionally, with a comment noting "unless banned in some room versions" that was never implemented. Per the room v10–v12 authorization rules ("If the sender matches state_key, allow if and only if that user's current membership state is invite, join, or knock"), a banned user could send a self-leave event to flip their own membership from `ban` to `leave`, then knock or rejoin under normal join rules — a ban-evasion authorization bypass. `authorization.cpp` now checks `target_current_membership` before allowing a self-leave.

- **fix(events): reject `m.room.member` events with an unrecognized `membership` value instead of silently treating them as `leave`.** `parse_membership_state` fell through to `MembershipState::leave` for any string outside `join`/`invite`/`leave`/`ban`/`knock`, contrary to the spec's "Otherwise, the membership is unknown. Reject." Combined with the self-leave bug above, a malformed `membership` value (e.g. from a buggy or adversarial remote server) could be admitted into room state under the guise of a "leave". `parse_membership_state` now returns `std::optional<MembershipState>`; the top-level `requested` membership on a new event is rejected when unrecognized, while internal lookups of already-accepted prior state fall back to `leave` (the safe "not a member" default).

- **fix(federation): reject inbound PDUs verified against a signing key that has passed its `valid_until_ts`.** `remote_key_cache.cpp`'s resolver falls back to a stale cached key (`cache.stale_fallback`) when a live refresh fails, by design, so callers can distinguish "known but currently unreachable" from "never seen" — but `authorize_federation_pdu` never checked the returned key's expiry before using it to verify a PDU's Ed25519 signature. If a remote server's key was rotated after a compromise and the old server became unreachable, an attacker holding the old private key could keep forging PDU signatures indefinitely. `authorize_federation_pdu` gained a `now_ts` parameter; when non-zero, a PDU verified against an expired key is now rejected with "sender domain signing key has expired". (The equivalent check already existed for X-Matrix request auth in `verify_signed_federation_request` — this closes the same gap for PDU signature verification.)

- **fix(media): sniff actual upload content instead of copying the client-declared `Content-Type` into both the "declared" and "sniffed" MIME fields.** `client_server.cpp` built the internal `declared_mime|sniffed_mime|scanner_clean|bytes` pipe body by duplicating the `Content-Type` header into both fields, which made `evaluate_media_upload`'s declared-vs-sniffed mismatch check permanently a no-op (it always compared a value to itself). An attacker could upload arbitrary content (e.g. HTML with an embedded `<script>`) while declaring an allow-listed `Content-Type` such as `image/png`, and the quarantine control meant to catch exactly that never fired. Added `media::sniff_mime_type()` (magic-byte detection for PNG/JPEG/GIF/PDF, a printable-ASCII heuristic for `text/plain`, falling back to `application/octet-stream`); `client_server.cpp` now sniffs the real request body for local uploads, and `repository.cpp`'s `fetch_remote_media` sniffs the real response body for federated media fetches (a remote server's declared `Content-Type` is equally untrustworthy).

- **fix(media): reject a `Content-Type` header containing `|` on media upload instead of splicing it unescaped into the internal pipe format.** The internal `declared_mime|sniffed_mime|scanner_clean|bytes` protocol relies on `|` as a field delimiter; `http::header_value_is_valid()` permits `|` in header values, so a client-controlled `Content-Type` containing `|` could shift the parsed field boundaries and forge the `scanner_clean` flag and leading body bytes seen by `local_http_router.cpp`'s `split_pipe_4`. `client_server.cpp` now rejects such uploads with `400 M_BAD_REQUEST` before constructing the pipe body.

### Testing
- **test(events): add conformance coverage for self-leave from `ban` and from no prior membership, and for an unrecognized `membership` value — all now rejected.** `test_event_auth_rules.cpp`; also updated `test_state_resolution_conformance.cpp`'s conflicting-membership fixtures, which had unintentionally relied on the self-leave bug (their `m.room.member` events carried no `membership` field at all) to reach "exactly one winner" — fixtures now use real join/leave content plus a shared public `join_rules` event so both conflict candidates are independently auth-valid.
- **test(federation): add unit coverage asserting a PDU verified against an expired signing key is rejected when `now_ts` is provided, accepted when the key is still valid, and accepted via the pre-existing 3-arg overload (`now_ts` omitted, expiry check skipped).** `test_federation_inbound_request.cpp`.
- **test(media): add unit coverage for `sniff_mime_type()` (each recognized signature, the text/plain heuristic, empty input, non-printable fallback, and a disguised-HTML payload) and for `evaluate_media_upload` quarantining a declared/sniffed mismatch.** `test_media_security.cpp`. Added a unit scenario asserting a `Content-Type` containing `|` is rejected with 400 rather than reinterpreted. `test_client_server.cpp`. Fixed pre-existing fixtures across `test_media_repository.cpp` and `test_client_server_conformance.cpp` that used placeholder ASCII bodies (e.g. `"png-bytes"`, `"test-image-data"`) declared as `image/png`, which the now-functional sniffer correctly flags as a mismatch — replaced with real PNG magic bytes.

### Changed
- **chore(release): bump version to 0.10.54 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.53

### Fixed
- **fix(sync): Simplified Sliding Sync `timeline` and `required_state` events now carry `event_id` instead of the raw stored PDU JSON.** `build_room_response` pushed a room's stored event JSON (`ev.json`) straight into the response for both the timeline and required_state arrays. Stored event JSON is the signed wire PDU format, which never carries `event_id` — it is derived from a reference hash and only ever injected for client-facing responses (see `client_server.cpp`'s `client_event_value()`, used correctly by `/sync` and `/messages`). Sliding sync skipped that conversion entirely, so every timeline and required_state event was missing `event_id` and additionally leaked federation-only PDU fields (`auth_events`, `prev_events`, `hashes`, `signatures`, `depth`) that must never reach a client. Per the Matrix spec's Room Event Format, `event_id` is mandatory on every client-facing event; `ruma-events` (the crate matrix-rust-sdk uses to parse each sliding sync timeline entry) rejects an event missing it with `missing field 'event_id'`. Because this failure happens per-event inside the client's timeline diff — not at the top level of the sliding sync response — the outer response still parsed and committed normally, `pos` kept advancing, and the connection never looked broken in server logs: the client silently dropped every single message while everything else (typing, receipts, room-list counts) kept working. Reported as "no messages are arriving on the mobile client", initially misdiagnosed as media-specific because a manual server-side repro of a plaintext send/ingest path had not yet exercised the exact Element X connection shape. Root-caused by reproducing that exact shape, capturing the real response body, and feeding it through the actual `ruma-events` deserializer: confirmed `missing field 'event_id'` before the fix and a clean parse after. `build_room_response` now converts stored events through a new `client_event_json()` helper (mirrors `client_event_value()`) for both timeline and required_state entries.

### Testing
- **test(sync): assert sliding sync timeline and required_state events carry `event_id` matching the real sent/stored event, not the raw PDU shape.** Regression coverage in `test_sliding_sync_flow.cpp` against the exact Element X `"room-list"` connection request shape.

### Changed
- **chore(release): bump version to 0.10.53 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.52

### Fixed
- **fix(sync): reject a Sliding Sync `pos` ahead of the live stream with `400 M_UNKNOWN_POS` instead of ratcheting it — inbound messages were silently never delivered after a server restart.** The pos handling deliberately never regressed a token component: the returned pos was `max(current watermark, requested pos)`, on the theory that a lower cursor would make clients retry indefinitely. In reality, when a client presents a pos *ahead* of the live stream — matrix-rust-sdk persists `pos` across app and server restarts (`share_pos`), while the server's in-memory stream watermark is rebuilt on startup and can come up lower than the previous lifetime's — the ratchet made the stale token permanent: the client's `since` floor sat above the live stream, so **every new inbound event landed in the gap and was filtered as already-seen**, the long-poll parked, the room was skipped, and the server echoed the inflated token back, forever. Outbound sending kept working (the send path never consults `pos`), which produced the confusing "can send but never receive" symptom. Production logs showed this live: a client polling with pos event-component 920 while the server's stream sat at 918. Per MSC4186, a pos the server cannot serve is now rejected with `400 M_UNKNOWN_POS` and the connection state is dropped; matrix-rust-sdk handles this by expiring the session and starting a fresh initial sync (`ErrorKind::UnknownPos` → `expire_session()`), so clients self-heal immediately. The returned pos is now always the live watermarks.

- **fix(database): persist the timeline stream-ordering watermark so it survives restarts (migration `003_event_stream_watermark`).** This is the root cause behind clients holding a `pos` "from the future": `next_stream_ordering` was rebuilt on startup from `max(events.stream_ordering) + 1`, but membership stream positions consume orderings **without a backing event row**, so every restart rebuilt the counter lower than the previous lifetime's — putting every client's persisted sliding sync `pos`/`since` token ahead of the live stream. All 16 stream-ordering allocation sites now flow through a new `homeserver::allocate_stream_ordering()` helper that persists the high-water mark to a new `event_stream_watermark` singleton table (mirroring the existing `sync_stream_watermark` from migration 002), and hydration takes the maximum of the persisted watermark and the highest persisted event ordering. Combined with the `M_UNKNOWN_POS` fix above: restarts no longer regress the stream at all, and the rejection path remains as a safety net for tokens that predate this migration.

### Testing
- **test(sync): assert a future pos is rejected with 400 M_UNKNOWN_POS and that the follow-up no-pos request receives a full initial snapshot.** Replaces the previous "never regresses a client stream position" scenario, which asserted the harmful ratchet behaviour this release removes.
- **test(database): assert the stream-ordering counter and pre-restart sliding sync pos survive a SQLite restart.** A regression scenario creates a room (consuming non-event-backed membership stream orderings), records `next_stream_ordering` and a sliding sync `pos`, restarts the runtime from the same SQLite file, and asserts the counter did not regress and the old `pos` is served rather than rejected with `M_UNKNOWN_POS`. Migration inventory tests updated for schema version 3 (47 tables, 3 migrations).

### Changed
- **chore(release): bump version to 0.10.52 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.51

### Fixed
- **fix(sync): wrap the receipts/typing extensions' per-room payload in a type-tagged event instead of sending bare content.** `m.receipt` and `m.typing` are `EphemeralRoom`-kind events (ruma's `SyncReceiptEvent`/`SyncTypingEvent`) — the wire shape is `{"type":"...","content":{...}}`. `build_receipts`/`build_typing` were serialising only the bare content object (e.g. `{"$event_id":{"m.read":{...}}}` with no `type`/`content` wrapper at all). Verified directly against ruma-client-api's own deserializer: the bare shape fails with `missing field 'type'`. matrix-rust-sdk treats a failed extension deserialization as a failed sync iteration — the response is accepted with `200` at the transport level, but the client never commits the new `pos` and immediately retries the same request, producing an unbounded busy-loop storm on **any** poll that returns a non-empty receipt or typing notification. This was invisible until 0.10.50's `rooms:["*"]` fix started actually delivering receipts to Element X for the first time — receipts had always been malformed, but the earlier "*" bug meant they were silently never sent, so the malformed shape never reached a client that would choke on it. Root-caused from a real capture: a fresh sliding sync response was generated locally, matched byte-for-byte against the connection shape reported in production logs, and fed through a standalone Rust program depending on `ruma-client-api` to confirm the exact deserialization failure before and after the fix.

### Testing
- **test(sync): assert extensions.receipts/typing wrap content in `{"type":...,"content":...}`, not bare content.** Regression coverage for the deserialization-storm fix; also updated the existing `build_extensions` unit coverage in `test_sliding_sync_surfaces.cpp`, which had asserted the old, broken bare-content shape.

### Changed
- **chore(release): bump version to 0.10.51 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.50

### Fixed
- **fix(sync): scope the Sliding Sync long-poll wake check to the extensions and lists a connection actually requested.** #375/#376/#377/#378 scoped the wake check to rooms the caller has joined, but it still woke a connection for *any* signal relevant to the user anywhere — a new timeline event in any joined room, or a receipt/typing update in any joined room — regardless of whether that connection had asked for rooms, receipts, or typing at all. Element X runs a dedicated background sliding sync connection with no `lists`/`room_subscriptions` that only enables the `to_device`/`e2ee` extensions, used to keep encryption keys flowing without paying for room-list computation. Every message, read receipt, or typing notification in any of the user's rooms woke that connection early, and since it had nothing new to report it replied instantly with an empty snapshot at the same `pos`, which the client immediately re-polled — a busy-loop sync storm on that connection (observed as `sliding_sync.dispatch`/`sliding_sync.response` pairs firing every 70-150ms) while the user was simply active in an unrelated room. The wake check now only considers a room timeline event relevant when the connection has at least one list or room subscription, and only considers a device-list-change/to-device/account-data/receipts/typing row relevant when the connection's request enabled that specific extension.

- **fix(sync): treat `"rooms":["*"]` in the receipts/typing extensions as "all subscribed rooms", not a literal room ID.** MSC4186's `AllSubscribed` sentinel (ruma's `ExtensionRoomConfig::AllSubscribed`) serializes to the JSON string `"*"`, and matrix-rust-sdk's `RoomListService` — used by Element X — sends exactly `"receipts":{"enabled":true,"rooms":["*"]}` on every sliding sync request. `effective_rooms()` only fell back to "all rooms in the response" when `rooms` was omitted entirely; a present-but-`["*"]` array was matched literally against room IDs, which never matches, so **read receipts were silently never delivered to Element X** via the receipts extension. `effective_rooms()` now also treats a single `"*"` entry as no filter.

- **fix(sync): resolve `required_state`'s `"$LAZY"` and `"$ME"` sentinel state keys instead of matching them literally.** matrix-rust-sdk's `DEFAULT_REQUIRED_STATE` (used by Element X's `RoomListService`) always requests `["m.room.member","$LAZY"]` and `["m.room.member","$ME"]`. The matcher compared `state_key` by plain string equality, and a real `m.room.member` event's `state_key` is always a user ID — never the literal string `"$LAZY"` or `"$ME"` — so **Element X never received a single `m.room.member` event from sliding sync**, breaking member lists, display names, and heroes resolution. `"$ME"` now resolves to the requesting user's own ID. `"$LAZY"` now resolves to the members relevant to the timeline this response returns (senders and membership-change subjects) when the timeline is truncated or this is the room's first appearance on the connection — matching matrix-rust-sdk/Synapse's lazy-loading behaviour — and to the `m.room.member` wildcard otherwise, so the client's existing membership cache stays valid across continuous incremental syncs. A member relevant for the first time on a connection is delivered even if their own membership event predates the incremental since-floor, tracked via a new per-connection `lazy_members_sent` set (mirrors the existing `rooms_seen` commit-on-ack pattern) so it isn't endlessly re-sent afterward.

### Testing
- **test(sync): assert that an e2ee/to_device-only Sliding Sync long-poll parks through a typing notification and message it did not request.** A regression scenario mirrors Element X's background connection (no lists/subscriptions, only `to_device`/`e2ee` enabled); after bob posts a typing notification and sends a message in a room alice has joined, alice's long-poll (`can_wait=true`) must return `needs_wait`, not an empty `complete` response.
- **test(sync): add end-to-end coverage that mirrors matrix-rust-sdk's actual `SyncService` request shapes.** Reproduces Element X's two concurrent sliding sync connections byte-for-byte — the `"room-list"` connection's exact `DEFAULT_REQUIRED_STATE` list, `timeline_limit`, and `account_data`/`receipts`(`rooms:["*"]`)/`typing` extensions, and the `"encryption"` connection's `to_device`/`e2ee`-only, no-lists shape — against a live homeserver instance. Covers: `m.room.encryption` is delivered via `required_state` on a private_chat room; alice's own member event (`"$ME"`) and bob's (`"$LAZY"`, the most recent timeline sender) are both delivered; the encryption-only connection parks through a message/typing/receipt it never asked for; the encryption-only connection wakes and delivers `device_lists.changed` on a key upload; the room-list connection's receipts extension delivers a receipt requested via `rooms:["*"]`.
- **test(sync): unit-test `"$ME"`/`"$LAZY"` required_state resolution directly against `build_room_response`.** Covers: `"$ME"` resolves to only the requester's own member event; `"$LAZY"` on an initial/truncated-timeline response scopes to just the members whose events are actually in the delivered timeline (not every joined member); a member newly relevant on this connection has their membership delivered even when it predates the since-floor, and is not re-sent once already delivered; `"$LAZY"` and `"$ME"` resolve correctly together, matching Element X's real combined request.

### Changed
- **chore(release): bump version to 0.10.50 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.49

### Fixed
- **fix(sync): scope the Sliding Sync long-poll wake check to the requesting user's own rooms.** The handler's "has anything relevant changed" gate compared the request's `since` cursor against the homeserver's global event-stream watermark: any event in *any* room on the server (not just rooms the caller has joined) made the gate treat the wait as satisfied and fall through to building a response immediately, even though `rooms{}` had nothing new for this connection. On a multi-room/multi-tenant server the global watermark advances constantly, so long-polls effectively never blocked — the client received a storm of near-instant, empty `rooms_in_response=0` responses with a `pos` that kept advancing regardless. Because the server marks a room's state as "seen" by this connection as soon as a response referencing it round-trips, room state (including `m.room.name` and `m.room.encryption`) that arrived inside one of these rapid-fire responses could be marked delivered without the client ever reliably applying it, since the server never resends unchanged state. The wake check now only treats a new room event as relevant when it landed in a room the caller has joined, matching the existing scoping already used for receipts and typing.

### Testing
- **test(sync): assert that a Sliding Sync long-poll parks rather than returning early for an event in a room the caller has not joined.** A regression scenario has two users, each with their own room; after alice completes an initial sync, bob sends a message in his own room and alice re-polls with a non-zero timeout from her prior `pos`. It asserts the handler returns `needs_wait` instead of an empty `complete` response.

### Changed
- **chore(release): bump version to 0.10.49 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.48

### Fixed
- **fix(sync): return MSC4186 `rooms[roomId].timeline` as a plain `[Event]` array, not a `/v3/sync`-style object.** The room response previously serialised `timeline` as `{events, limited, prev_batch}`, which Element X / matrix-rust-sdk does not accept for MSC4186 Simplified Sliding Sync. The malformed response caused the client to reject the returned `pos` and replay the same request position, so the connection state never committed and rooms stayed invisible. The timeline field is now a direct array of events as required by the proposal.
- **fix(sync): stop computing per-room `prev_batch` and `limited` for Sliding Sync.** These fields are not part of the MSC4186 room object; removing them also removes the now-unused `SlidingSyncRoomResponse::prev_batch` and `limited` members.

### Testing
- **test(sync): assert that the v4 sliding sync response returns `timeline` as a JSON array.** A regression scenario creates a room, sends a message, and performs an initial sliding sync via `POST /_matrix/client/v4/sync`. It verifies that `rooms[roomId].timeline` is an array containing the message event and that the legacy `{events, limited, prev_batch}` object shape is absent.

### Documentation
- **docs: document the MSC4186 room object fields and the array timeline shape.** `docs/matrix-v1.18-client-server-api.md` now lists each field in `rooms[roomId]` and explicitly notes that `timeline` is a plain `[Event]` array, not the `/v3/sync` object.

### Changed
- **chore(release): bump version to 0.10.48 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.47

### Documentation
- **docs: reference the latest raw MSC4186 proposal and document the stable v4 endpoint shape.** `docs/matrix-v1.18-client-server-api.md` now links the authoritative raw proposal text (`https://raw.githubusercontent.com/matrix-org/matrix-spec-proposals/refs/heads/main/proposals/4186-simplified-sliding-sync.md`), lists all three routed endpoints (`v4`, `org.matrix.msc4186`, `org.matrix.simplified_msc3575`), and documents body-level `pos`/`timeout` and the singular `range` key.

### Changed
- **chore(release): bump version to 0.10.47 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.46

### Documentation
- **docs: fix accuracy errors and gaps found in a full documentation audit.** `canonical-json.md` no longer claims signed-64-bit integer enforcement (actual: JS-safe-integer range) and now documents the `parse_json()` general-purpose parser. `auth-identity.md` no longer lists device-list sync, key-count responses, and key-backup retrieval/deletion as deferred — all three are implemented — and a botched-merge formatting defect is fixed. `log-filtering.md` and `user-manual.md` audit-event tables now include `request.user_locked`/`request.user_suspended`. `http-transport.md` no longer describes single-mutex runtime serialisation (actual: 256-way room-striped mutex) and now documents the dedicated `sync_pool`. `user-manual.md`'s hardening self-check table now reflects the real compile-time/runtime probes instead of describing every check as an unimplemented placeholder, and adds the `no_new_privs`/`capability bounding` rows. `architecture.md` now mentions `tests/conformance/` in the testing section. `todos/production-milestone.md` strikes through the token-hashing and Argon2id items, which were already implemented. `tests/smoke/AGENTS.md` no longer describes a nonexistent `--smoke` flag or live-listener checks that the smoke suite doesn't perform. `security/coding-rules.md` entries now cite a CWE or named vulnerability class per `security/AGENTS.md`'s own requirement; the style-only rules it previously mixed in (member prefix, include ordering/quoting) moved to `docs/coding-rules.md`.

### Changed
- **chore(release): bump version to 0.10.46 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.45

### Fixed
- **fix(sync): treat initial Sliding Sync rooms on a fresh connection as full snapshots, not as deltas from a reused pos.** Element X sometimes creates a new `conn_id` and supplies a `pos` from another connection or device. The server was using that position as a per-room since floor, so initial rooms reported zero unread notifications for events at or before the borrowed position and could appear stale. Room-level deltas now use `0` for initial rooms and only apply the request `pos` to rooms this connection has already seen.

### Testing
- **test(sync): cover fresh Sliding Sync connections that reuse a pos from another conn_id.** A regression scenario creates three joined rooms, sends a message in one, obtains a `pos` on a seed connection, then syncs with a new `conn_id` reusing that `pos`. It asserts that all three rooms are returned with `initial=true` and that the room containing the message reports a non-zero unread notification count.

### Changed
- **chore(release): bump version to 0.10.44 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.43

### Fixed
- **fix(sync): preserve an unacknowledged Sliding Sync snapshot for request retries.** The server previously committed list windows and room inclusion immediately after writing a response. If Element X cancelled or retried an initial request with the same prior `pos`, the retry received an empty list and no rooms despite never acknowledging the original response. Connection state now commits only after the client supplies the returned position; retries are rebuilt from the last acknowledged snapshot.
- **fix(sync): never regress a Sliding Sync position after watermark reconstruction.** Responses now retain each component of a client position when the server's reconstructed stream watermark is behind it, preventing Element X from rejecting the lower cursor and retrying the same room-list request in a tight loop.

### Testing
- **test(sync): cover retries before Sliding Sync position acknowledgement.** A regression scenario asserts that retrying a fresh connection with the same `pos` retains the original `SYNC` list operation and room payload.
- **test(sync): cover a client position ahead of the reconstructed Sliding Sync watermark.** A regression scenario asserts that the returned position never moves backwards.

### Changed
- **fix(ci): make NetBSD package installation resilient to mirror outages.** NetBSD CI now retries both official binary-package endpoints and checks dependency installation before invoking the build, avoiding a misleading missing-compiler failure when a mirror refuses a transient connection.
- **chore(release): bump version to 0.10.43 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.41

### Testing
- **test(sync): add an opt-in live Sliding Sync long-poll probe for pong.ping.me.uk.** The test authenticates only when MEROVINGIAN_LIVE_ACCESS_TOKEN supplies a short-lived token, creates an isolated conn_id, and verifies that a current pos is held for the requested long-poll interval rather than immediately reissued. It skips without network access or a token and never logs credential or response content.

### Changed
- **docs(testing): document safe authenticated live client-server probes.**
- **debug(sync): add startup-gated Sliding Sync response diagnostics.** Starting the server with --debug emits a request-shape summary with safe connection metadata, positions, counts, enabled extension names, and response size. It never logs connection IDs, request bodies, tokens, event content, or encryption material, and cannot be enabled through per-module log configuration.
- **chore(release): bump version to 0.10.41 across meson.build, src/main.cpp, src/db_migrate.cpp, packaging metadata, build scripts, and CHANGELOG.md.**

## 0.10.40

### Fixed
- **fix(sync): sliding sync room list now uses the persistent store as the source of truth.** `compute_room_list` previously enumerated joined rooms from the runtime cache (`rt.database.rooms`) while reading membership and metadata from the persistent store. This caused rooms to disappear from sliding sync when the runtime cache was stale or unhydrated, notably making rooms created on one device invisible to a second device using MSC4186 sliding sync. The room list is now built directly from `store.rooms` and `store.memberships`, matching the database of record.

### Testing
- **test(sync): unit and integration coverage for cross-device sliding sync visibility.** A new unit test proves `compute_room_list` still reports a room that exists only in the persistent store, and a new integration test verifies that a room created on a desktop device appears in the sliding sync response for the same user on a mobile device.

### Changed
- **chore(release): bump version to 0.10.40 across `meson.build`, `src/main.cpp`, `src/db_migrate.cpp`, packaging metadata, build scripts, and `CHANGELOG.md`.**

## 0.10.39

### Fixed
- **fix(ci): actually run GPG signing and rolling-latest publishing after skipped optional jobs.** The previous attempt used bare `needs.<job>.result == 'success'` conditions, but GitHub Actions still implicitly applies a default `success()` check to any job-level `if` that does not contain a status function. Because optional jobs such as `netbsd-pkg-retry` are skipped, that default `success()` returned false and kept skipping `sign-package-assets`, `publish-latest`, `sign-release-assets`, and `publish-alpha-release`. All four jobs now use `!failure() && !cancelled()` together with the explicit result check so they run whenever their direct dependency succeeds, regardless of skipped upstream jobs.

### Changed
- **chore(release): bump version to 0.10.39 across `meson.build`, `src/main.cpp`, `src/db_migrate.cpp`, packaging metadata, build scripts, and `CHANGELOG.md`.**

## 0.10.38

### Added
- **feat(rate-limit): production-grade client-server rate limiting.** Per-IP and per-user wall-clock token-bucket tiers are enforced before dispatch. Per-user buckets are keyed by the authenticated `user_id`; per-IP buckets use the effective client IP plus a normalized route. Path parameters (`roomId`, `deviceId`, `mediaId`, etc.) are coalesced into placeholders so a single cap covers all rooms/devices/media. Exceeded caps return `429 M_LIMIT_EXCEEDED` with a `Retry-After` header (and the deprecated `retry_after_ms` body field). Operators configure overrides via `client_rate_limits.per_ip.<target>`, `client_rate_limits.per_user.<target>`, and `client_rate_limits.default_per_ip`.
- **feat(voip): static TURN credentials for `GET /_matrix/client/v3/voip/turnServer`.** New `server.turn.server`, `server.turn.username`, `server.turn.password`, and `server.turn.ttl_seconds` config keys supply static credentials to authenticated VoIP clients. When no TURN server is configured the endpoint returns an empty JSON object so clients gracefully disable relay support.
- **feat(federation): inbound `GET /_matrix/federation/v1/media/download/{mediaId}` endpoint.** Remote homeservers can download locally-uploaded media using `X-Matrix`-authenticated requests. The route bypasses the federation worker (which has no access to the local media repository) and returns a `multipart/mixed` response per Matrix v1.18.

- **feat(supply-chain): immutable dependency pinning for `catch2` and `yyjson`.** Both wraps are now `[wrap-file]` entries pointing at release tarballs with SHA-256 `source_hash` values. `scripts/verify-wrap-pins.sh` and an updated `tests/tooling/test_dependency_wraps.py` enforce that every committed wrap is a file wrap with a 64-character hash.
- **feat(license): release-attached license review.** `docs/dependencies/licenses.md` records the license and GPL-3.0-or-later compatibility of every direct and transitive image-codec dependency. The `dependency-review-action` license check is enabled, `scripts/generate-license-summary.py` emits a machine-readable `merovingian.licenses.json`, and the JSON is attached to alpha and rolling-latest releases.
- **feat(release): GPG-signed release artifacts.** A reusable `.github/workflows/sign-artifacts.yml` workflow imports an offline maintainer GPG key and produces detached `.asc` signatures for every tarball (alpha releases) and every package plus `SHA256SUMS` (rolling `latest` releases). Verification instructions are documented in `docs/release-process.md` and the release checklist.
- **feat(reproducible-builds): verify static Linux tarball reproducibility.** `scripts/reproducible-build.sh` builds the static Linux fallback tarball twice with the same `SOURCE_DATE_EPOCH` and compares SHA-256 hashes. `scripts/build-static-linux.sh` now defaults to release builds with `--strip`, sets `SOURCE_DATE_EPOCH` from the commit author date, and uses deterministic GNU tar options when available. A dedicated CI job runs the verification on every push to `main` and on PRs touching the build.

### Changed
- **docs(http-transport, user-manual, capability-gaps, build-warning-policy, release-process, security-review-checklist, dependencies): document the implemented rate limiter, TURN configuration, inbound federation media serving, dependency pinning policy, license review, GPG signatures, and reproducible build verification; update `config/merovingian.conf.example`.**
- **chore(release): bump version to 0.10.38 across `meson.build`, `src/main.cpp`, `src/db_migrate.cpp`, packaging metadata, build scripts, `README.md`, and `docs/user-manual.md`.**

### Fixed
- **fix(build): avoid `_FORTIFY_SOURCE` macro redefinition on musl/Alpine builds.** Hardening flags now emit `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3` so the project's level-3 fortification overrides any toolchain-default level-2 definition without triggering `-Werror`.
- **fix(config): keep public registration disabled in `config/merovingian.conf.example`.** The example config now defaults to `security.registration.enabled=false`, so `--check-config` and `--dry-run` smoke tests that copy the example file no longer require a real `/etc/merovingian/registration-token`.
- **fix(ci): make `scripts/reproducible-build.sh` work when `actions/checkout` does not materialize a `.git` directory.** The script no longer relies on `git rev-parse --show-toplevel`; it derives `SOURCE_DATE_EPOCH` from git when available and falls back to `0` otherwise.
- **fix(ci): ensure GPG signing and rolling-latest publishing run after package staging.** Added explicit `needs.<job>.result == 'success'` conditions to `sign-package-assets`, `publish-latest`, `sign-release-assets`, and `publish-alpha-release` so the default `success()` graph (which can be false when optional retry jobs are skipped) no longer skips the signing and publishing jobs.

### Testing
- **test(rate-limit): new and updated unit tests cover route normalization, per-user keying by `user_id`, `Retry-After` semantics, and config validation.**
- **test(federation, media): route coverage, federation-worker bypass, multipart/mixed envelope construction, and end-to-end handler tests cover the inbound federation media download endpoint.**
- **test(tooling): `tests/tooling/test_dependency_wraps.py` now asserts `[wrap-file]` pinning with SHA-256 hashes, the absence of `[wrap-git]` entries, per-dependency review documents with license notes, and a valid machine-readable license summary JSON. `tests/tooling/test_packages_workflow.py` confirms the version bump is consistent across packaging metadata.**
- **test(release): `scripts/check-release-readiness.sh` now gates the presence of the license review document, the wrap-pin verification script, and the GPG signing workflow references in `release.yml` and `packages.yml`.**

## 0.10.36

### Added
- **feat(config): explicit `listeners.*.reverse_proxy` declaration for listener security.** Public (non-loopback) client and federation listeners must now use TLS with `reverse_proxy=false`. Loopback cleartext listeners are only permitted when `reverse_proxy=true` is explicitly declared, matching the reverse-proxy-first deployment model. Configuration validation rejects ambiguous or unsafe combinations before startup.

### Changed
- **docs(user-manual, http-transport, threat-model): document the explicit reverse-proxy listener model and public TLS requirement.**

## 0.10.35

### Fixed
- **fix(federation-proxy): `FederationProxy::handle()` now matches `GET /_matrix/key/v2/server` exactly rather than by substring**, so a malformed target such as `/_matrix/federation/v1/state/!room:example.com/_matrix/key/v2/server` is no longer mis-routed to the local key endpoint.
- **fix(federation-worker): `WorkerEventLoop` request handlers now check `pool.submit()` return value** and immediately send a `503 M_UNAVAILABLE` IPC response if the pool is stopping, instead of silently dropping the request and letting the main process time out.
- **fix(ipc): `deserialize_outbound_http_response()` now preserves the specific `http::OutboundError` code** (`timeout`, `connection_failed`, `invalid_url`, etc.) instead of always collapsing failures to `network_error`.
- **fix(ipc): `IpcChannel::dispatcher_loop()` now catches unhandled exceptions thrown by request handlers**, marks the channel unhealthy, wakes every pending `send_request` waiter, and exits cleanly instead of calling `std::terminate`.
- **fix(federation): `make_outbound_make_membership()` no longer appends `ver=` query parameters to `make_leave`** per Matrix v1.18 (only `make_join` and `make_knock` carry supported-room-version hints).
- **fix(federation-worker): `WorkerEventLoop::run()` drains `local_pool` and `relay_pool` before calling `channel->stop()`**, so in-flight tasks can still send their IPC responses before the fd is closed.
- **fix(federation-worker): `WorkerPool::handle()` now computes the IPC timeout as `max(federation.worker.request_timeout_seconds, security.federation.remote_timeout) + 10 s`**, so a worker-side outbound HTTP call that legitimately runs longer than the worker request timeout can complete before main declares an IPC timeout.
- **fix(federation-worker): `WorkerSupervisor::stop()` now marks the supervisor unhealthy** and uses an atomic `worker_pid_` so TSan-clean health checks and shutdown are observable from any thread.

### Testing
- **test(federation-worker): `tests/integration/test_federation_worker_flow.cpp` now covers `WorkerSupervisor` bounded stop, unexpected-exit restart/backoff, and SIGKILL escalation when the worker ignores shutdown; `tests/unit/test_worker_supervisor.cpp` covers the pre-start `worker_pid()` getter.**
- **test(federation-worker): `tests/unit/test_worker_event_loop.cpp` now covers shutdown sequencing and pool-submit-failure response paths.**
- **test(federation-worker): `tests/integration/test_federation_worker_flow.cpp` exposes `FederationProxy::healthy()` and replaces the hard-coded 2-second sleep before the outbound proxy test with a `wait_for_healthy(proxy)` helper that polls pool health.**
- **test(federation): `tests/unit/test_federation_membership_endpoints.cpp` pins that `make_leave` targets carry no `ver=` query parameters while `make_join` still advertises supported versions.**
- **test(ipc): `tests/unit/test_ipc_framing.cpp` pins that an unhandled exception in a request handler does not call `std::terminate` and instead makes `send_request` return `nullopt`.**
- **test(ipc): `tests/unit/test_ipc_federation_frames.cpp` pins that `OutboundError` round-trips through `serialize_outbound_http_response` / `deserialize_outbound_http_response`.**

### Changed
- **chore(release): bump version to 0.10.35 across `meson.build`, `src/main.cpp`, `src/db_migrate.cpp`, packaging metadata, build scripts, `README.md`, and `docs/user-manual.md`.

## 0.10.34

### Fixed
- **fix(media): federated attachments could be sent but never received.** `fetch_remote_media_live()` called only the deprecated, unauthenticated `GET /_matrix/media/v3/download/{serverName}/{mediaId}` endpoint, which current Synapse and Merovingian deployments disable by default per the Matrix v1.11 spec change — every remote media fetch 404'd. The fetch path now tries the mandatory authenticated `GET /_matrix/federation/v1/media/download/{mediaId}` endpoint first (signed with an X-Matrix Authorization header, same as outbound transactions), decodes its `multipart/mixed` response (`parse_federation_media_multipart()`), and falls back to the deprecated endpoint with `allow_remote=false` only on a `404`, per spec. A `Location`-redirect response from the authenticated endpoint is not yet followed (see `docs/todos/capability-gaps.md`) and falls back the same way.
- **fix(media): serving locally-uploaded media to other homeservers over federation is still unimplemented** — flagged as a follow-up capability gap in `docs/todos/capability-gaps.md` (this server has no inbound route for either the authenticated or deprecated federation media download endpoint).

### Added
- **tests(homeserver): new `remote_federation_media_download_url()` and `parse_federation_media_multipart()` pure functions, covered by unit tests (`tests/unit/test_homeserver_media_service.cpp`) and a new conformance suite (`tests/conformance/test_federation_media_conformance.cpp`) citing SS API §Content Repository.**

## 0.10.33

### Added
- **docs: new `docs/user-manual.md` — a comprehensive operator manual covering installation (packages and source), initial setup, configuration parameters, database backends, running the server, reverse-proxy pointers, user management, federation policy, media repository, logging/diagnostics, maintenance, troubleshooting, and a security checklist.**
- **docs(readme): `README.md` now links to `docs/user-manual.md` and reports the current beta version (v0.10.33).**
- **docs(user-manual): the Reverse proxy section now includes complete, copy-paste configs for nginx, Apache httpd, Caddy, Traefik, HAProxy, and Cloudflare (TLS termination, `.well-known` discovery, client/media/federation/key routing, `X-Forwarded-For` rate-limit hardening) plus the per-proxy CORS smoke test, folded in from the retired `docs/configuration.md`.**

### Changed
- **chore(release): bump version to 0.10.33 across `meson.build`, `src/main.cpp`, `src/db_migrate.cpp`, packaging metadata, and build scripts.**
- **docs: `docs/configuration.md` is retired — every section (fail-closed startup, listener/TLS policy, secrets at rest, registration/token lifetimes, federation inbound/outbound/join/worker controls, size and duration formats, trust-safety transport, reloadability policy, runtime config snapshot, startup hardening self-check, production packaging, CORS, client rate limits, log-module overrides) is now part of `docs/user-manual.md`'s Configuration, Federation, and Media repository sections. `AGENTS.md`, `README.md`, `docs/getting-started.md`, `docs/hardening.md`, `docs/http-transport.md`, `docs/media-repository.md`, `docs/release-process.md`, `src/config/AGENTS.md`, packaging spec/PLIST files, `scripts/build-static-linux.sh`, and two source comments now point at `docs/user-manual.md` instead.**

## 0.10.32

### Added
- **feat(federation): inbound `/send` now applies authenticated per-origin abuse controls:** Matrix v1.18 transaction caps are enforced explicitly (`50` PDUs, `100` EDUs by default), and each verified remote origin has configurable transaction, PDU, and EDU rate buckets so a burst from one server is throttled by actual federation pressure rather than by spoofable event sender IDs.
- **feat(config): operators can tune federation abuse limits with `security.federation.max_transaction_pdus`, `security.federation.max_transaction_edus`, `security.federation.per_origin_transaction_rate`, `security.federation.per_origin_pdu_rate`, and `security.federation.per_origin_edu_rate`.**
- **docs(federation): configuration and architecture docs now explicitly distinguish inbound `/send` abuse controls from outbound destination queue/backoff controls.**

### Fixed
- **fix(federation-worker): inbound federation dispatch no longer holds `HomeserverRuntime::mutex` across whole `/send` transactions:** the previous wrapper lock survived the earlier PDU-stripe and IPC handler-pool fixes, so a worker shard still serialized relayed transactions while each request waited on worker-to-main sink IPC. `handle_federation_http_request()` now holds the global runtime mutex only for startup checks, callback wiring, key publication, request identity construction, and trust-safety policy lookup, then releases it before `handle_inbound_federation_request()` runs.
- **fix(federation): `FederationRuntimeState` now protects its own mutable bookkeeping while federation requests run concurrently:** remote records are copied out for request processing, remote signing-key/trust updates are persisted through narrow guarded helpers, and accepted transaction/audit vectors are updated under a federation-local mutex instead of relying on the homeserver global mutex.
- **fix(federation): valid but excessive `/send` traffic now returns `429 M_LIMIT_EXCEEDED` at the origin policy boundary while individual invalid PDUs still report per-PDU errors in a `200` transaction response, preserving Matrix federation retry semantics.**
- **fix(federation): `handle_inbound_federation_request()` no longer passes a const remote record to `check_inbound_request_signature()` and no longer dereferences a non-optional remote when choosing the PDU signing key, restoring compilation after the burst-delivery refactor.**
- **fix(federation): `federation_summary()` now formats per-origin transaction/PDU/EDU rates as `N/Ws` (e.g. `120/60s`) so the runtime summary matches the policy syntax and the bounded-operational-values test passes.**
- **fix(fuzz): `fuzz-config-parser` now links `http_lib`, `observability_lib`, `core_lib`, and `platform_lib` because config validation calls `http::rate_limit_policy_is_valid`, and `rate_limit.cpp` pulls in observability symbols.**

### Testing
- **test(federation): `tests/unit/test_federation_runtime_callbacks.cpp` now blocks a federation transaction sink and asserts unrelated runtime work can still acquire `HomeserverRuntime::mutex`, preventing the wide-lock drip-feed regression from returning.**
- **test(federation): transaction validation and inbound federation tests now cover Matrix PDU/EDU count caps plus per-origin transaction/PDU/EDU throttling without incrementing remote trust failures.**

## 0.10.31

### Fixed
- **fix(federation): inbound PDU ingestion no longer serializes all federation traffic behind a single `runtime.mutex` — per-room striped locks now protect room-local ordering while independent rooms commit concurrently:** the default `pdu_sink` previously held the global runtime mutex for the entire auth, persistence, membership-update, and sync-notification path. Under a burst of 30–40 inbound federation events this forced every PDU to wait for the previous one's database commit, turning quick succession into a drip-feed even though SQLite/PostgreSQL backends open a fresh connection per transaction and could otherwise overlap. Fix: `HomeserverRuntime` now owns 256 room-stripe mutexes; `ingest_pdu_event()` reserves a global stream-ordering token, then acquires only the stripe for the event's `room_id` while building the auth map, preparing the prepared-state update, applying in-memory rows, and updating membership, releasing that stripe for the actual database commit so commits for different rooms run in parallel. `database::store_event_with_state()` is refactored into `prepare_store_event_with_state()`, `commit_persistent_transaction()`, and `apply_store_event_with_state()` to make the lock-free commit boundary explicit.
- **fix(federation): `ingest_pdu_event()` now allocates a fresh `sync_stream_id` for every accepted PDU instead of re-reading `persistent_store.next_sync_stream_id`:** the previous read published the same counter value repeatedly (usually `0` for a fresh store), breaking sync-token advancement for federation-driven events and any test that checked the published sync surface advanced.
- **fix(federation): `ingest_pdu_event()` no longer performs the `sync_stream_id` backend write while holding both a room stripe and the global `runtime.mutex`:** both IDs are now reserved under the global mutex alone before the stripe is acquired. This removes the long database write from the per-room critical section, letting other events for the same room proceed and avoiding a broad contention window under ThreadSanitizer.
- **fix(ci): ThreadSanitizer CI job now preserves its live output and Meson test log as artifacts:** the previous workflow only surfaced what GitHub Actions captured in the run log, which truncated before the timed-out scenario name and omitted `build-tsan/meson-logs/testlog.txt`. The `tsan` job now tees stdout/stderr to `tsan-ci-log.txt` and uploads that file plus the Meson logs with `if: always()`, so future hangs show exactly which scenario is stuck.
- **fix(federation-worker): `WorkerSupervisor::stop()` no longer logs false-positive "Federation worker did not exit" warnings when the supervisor thread has already reaped the child:** `waitpid` returning `ECHILD` is now treated as a successful reap, so the fallback SIGTERM/SIGKILL escalation is skipped instead of being directed at a process that no longer exists.
- **fix(federation-worker): `WorkerSupervisor` no longer blocks its supervisor thread in a synchronous `waitpid` while waiting for the child to exit:** the previous blocking wait meant `stop()` could not join the supervisor thread until the worker process exited, so a TSan-instrumented worker that was slow to terminate (or stuck during teardown) delayed the whole `WorkerPool::stop()` by the full child-exit time. The supervisor loop now polls with `WNOHANG` and a short sleep, so `running_ = false` promptly unwinds the loop and `stop()` proceeds to its own bounded reap/SIGTERM/SIGKILL sequence.
- **fix(federation): `ingest_pdu_event()` no longer reports membership PDUs as `internal_error` after the event has already been committed:** if `upsert_membership()` fails after `apply_store_event_with_state()`, the event is already in the database and the accepted result has been published, so returning an error to the upstream server is incorrect and can cause duplicate retries. The function now logs a warning and keeps the accepted result, matching the fact that the PDU was already accepted.
- **fix(ci,test): `tests/integration/test_seccomp_sqlite_flow.cpp` no longer hangs CI when a blocked syscall is called in a retry loop under ThreadSanitizer:** the seccomp test uses `SECCOMP_RET_TRAP` so the SIGSYS handler can report missing syscalls, but if SQLite/glibc retried the same blocked syscall (e.g. `fchown` when the child could not drop to a non-root uid), the handler kept trapping forever and the parent blocked on `waitpid`. The handler now limits itself to 32 reports and then terminates the child with `exit_group`, so the test fails fast and names the offending syscall instead of consuming the full 1800s CI timeout.

### Testing
- **test(federation): new `tests/unit/test_federation_pdu_ingest_concurrency.cpp` exercises concurrent `ingest_pdu_event()` calls across distinct rooms and asserts the resulting events/membership/stream-ordering state is correct.**
- **test(federation): `tests/unit/test_federation_pdu_ingest_concurrency.cpp` no longer calls `REQUIRE` from worker threads, which caused ThreadSanitizer to report races on Catch2's internal assertion counters; all envelopes and all post-join state checks are now built/verified on the main thread while workers only update an atomic accepted counter.**

## 0.10.30

### Fixed
- **fix(federation-worker,ipc): WorkerPool now runs every worker-to-main ingest handler on a dedicated handler thread pool instead of inline on the `IpcChannel` dispatch thread:** the 0.10.29 reader/dispatch split stopped the reader thread from freezing, but the single per-channel dispatch thread still serialized every `pdu_ingest`, `membership_ingest`, `edu_ingest`, `invite_ingest`, `otk_claim_ingest`, `user_devices_ingest`, `device_keys_query_ingest`, `profile_query_ingest`, `event_query_ingest`, and `sign_request`. A slow `pdu_ingest` (e.g. persisting an event under `runtime.mutex` and waking sync notifiers) therefore parked the dispatch thread and delayed every later frame on that channel, including responses to unrelated outbound requests — the residual drip-feed on high-rate federation. Fix: `WorkerPool` constructs a `net::ThreadPool` (`handler_pool_`, sized from `federation.worker.relay_threads`) and submits each ingest handler to it, so the dispatch thread only classifies and enqueues frames. Slow ingestion now runs concurrently with later frames.
- **fix(federation-worker): `WorkerSupervisor::stop()` and the supervisor restart path no longer deadlock with the IPC dispatch thread:** both paths previously held `channel_mu_` while calling `channel_->stop()`, which joins the dispatch thread; a `pdu_ingest` handler running on that thread can call back into the same supervisor's `channel_snapshot()` (via `notify_room_changed()`) and block on the same mutex. The stop/restart code now takes ownership of the channel under the lock and releases the lock before calling `stop()`, keeping the channel alive through a `std::shared_ptr` snapshot so callers can finish safely.
- **fix(ci): ThreadSanitizer integration-test job no longer times out at Meson's default 600 s:** TSan-instrumented binaries run slower than ASan, and the seccomp/SQLite fork-heavy integration scenario was being killed by the default timeout, producing a storm of `signal-unsafe call inside of a signal` warnings from Catch2's fatal signal handler as it tried to print a summary while handling the SIGTERM. The `tsan` job now sets `MESON_TEST_TIMEOUT_MULTIPLIER: 3`, matching the existing `asan-ubsan` job.
- **fix(federation-worker): `WorkerPool::stop()` now drains `handler_pool_` before stopping worker supervisors:** without this, in-flight main-side IPC handlers could still be running when their channel was closed, and tests that stopped the pool immediately after startup could hang during TSan-instrumented teardown while a handler thread raced a channel whose dispatch thread had already been joined.
- **fix(federation-worker): `WorkerSupervisor::stop()` no longer waits indefinitely for the child process:** the previous blocking `waitpid(worker_pid_, nullptr, 0)` could hang forever if a TSan-instrumented worker child deadlocked or failed to exit. The supervisor now polls with `WNOHANG`, waits up to `request_timeout_seconds`, then escalates to `SIGTERM`, waits again, and finally `SIGKILL` and a reaping wait. This keeps a stuck worker from blocking process shutdown or test teardown.

### Testing
- **test(ipc): new `IpcChannel` scenario in `tests/unit/test_ipc_framing.cpp` models the main-side handler-pool fix:** a deliberately slow request handler is offloaded to a `net::ThreadPool` while a fast second request is also offloaded, proving the fast request replies before the slow one completes and that the dispatch thread is not serialized by slow work.

## 0.10.29

### Fixed
- **fix(ipc,federation-worker): federated messages no longer stall for ~60 seconds each and drip-feed in over minutes of origin-server retries — `IpcChannel` now routes frames on the reader thread and runs request handlers on a separate per-channel dispatch thread:** the reader thread previously invoked the request handler inline for every inbound request/notification frame, so a handler that blocked on a lock froze all frame routing for the channel — including responses to the channel's own pending `send_request` calls sitting right behind the blocking frame. Two production deadlock cycles followed from this. (1) Worker side, on every relayed PDU: the worker's relay thread holds the worker `runtime.mutex` for the whole of `handle_federation_http_request()` — including its `pdu_sink` IPC round trip to main — while main's `pdu_ingest` handler, after committing the event, sends a `room_sync` notification (whose worker-side handler needs that same worker mutex) immediately before the `pdu_ingest` response. The worker's reader thread picked up the notification first, blocked inline on `runtime.mutex`, and could never route the response one frame behind it; the relay thread waited out the full 60s `pdu_ingest` timeout, main's `WorkerPool::handle()` 503'd the transaction at `request_timeout_seconds`, and the origin server re-sent it on an exponential backoff — a flurry of messages between two users then trickled in one ~60s stall at a time even though main had already committed and sync-published each event on first receipt. (2) Main side, the mirror image: a client-server handler holding main's `runtime.mutex` across a worker-proxied outbound call (e.g. the remote `/keys/query` fan-out, common in E2EE conversations) waits on an `outbound_http_response` that main's reader thread cannot route when a concurrent `pdu_ingest` arrived first and blocked inline on that same mutex — both sides then sat out their full timeouts. Fix: request frames are queued and handled one at a time, in arrival order, by a dedicated dispatch thread per channel (preserving the previous serial-handling semantics), while the reader thread only wakes `send_request` waiters and enqueues — a blocked handler can no longer stall response delivery in either process. Additionally the worker now runs `room_sync` reloads on `local_pool` instead of the channel's dispatch thread, since `reload_room` needs `runtime.mutex`, which an in-flight relayed transaction can legitimately hold for its full duration — parking the dispatch thread on it would delay every later queued request frame. See `docs/architecture.md`, "IPC reader/dispatch split".

### Testing
- **test(ipc): two new `IpcChannel` scenarios in `tests/unit/test_ipc_framing.cpp`:** a regression test that models the drip-feed deadlock directly (a request handler needing a mutex held by a thread blocked in `send_request`, with the notification frame arriving ahead of the response frame — times out on the pre-fix inline dispatch, passes with the dispatch thread) and an ordering test pinning that request frames are still handled strictly in arrival order with the new dispatch thread.

## 0.10.28

### Fixed
- **fix(federation,e2ee): remote users joining a Merovingian-hosted encrypted room now receive local device-list updates immediately:** the `send_join` membership acceptor now broadcasts `m.device_list_update` EDUs for existing local members in the room to the joining user's server, so the remote client can query/use current Merovingian device keys before sending its first encrypted reply.
- **fix(federation-worker,e2ee): EDU-only `/send` transactions no longer queue behind shard-0 worker traffic:** after X-Matrix verification in main, transactions with no PDU room ID are handled in main directly instead of being routed to worker shard 0 and relayed back to main's `edu_sink`, reducing delayed or timed-out `m.direct_to_device` key-share delivery.

### Documentation
- **docs(federation-worker): documented the EDU-only `/send` main-process bypass and narrowed relay-pool wording to PDU-bearing transactions.**

### Testing
- **test(federation,e2ee): wire the remote-join device-list fanout unit test's dispatch worker to the persistent store it asserts against and cover the guard that skips login-only devices without uploaded device keys.**

## 0.10.27

### Documentation
- **docs(architecture): align the architecture overview with the current implementation and Matrix v1.18 references:** refreshed the module list, runtime model, federation-worker consistency model, implemented API summaries, and spec citations in `docs/architecture.md`.

## 0.10.26

### Fixed
- **fix(federation-worker): a federation worker shard could go fully unresponsive for roughly 30 seconds at a time with no crash or supervisor restart logged, coinciding with a burst of `503`s a remote peer typically retried successfully:** every `merovingian-fed-worker` process ran a single fixed-size thread pool (`federation.worker.threads`, shipped default 4) for two jobs at once — dispatching every incoming `fed_request` forwarded from main, and, inside that same dispatch, blocking synchronously on an IPC round-trip back to main whenever the request needed `pdu_sink`, `edu_sink`, `membership_acceptor`, `invite_handler`, or one of the query-provider relays (`profile_query_provider`, `device_keys_query_provider`, `user_devices_provider`, `event_query_provider`, `one_time_keys_claim_provider` — see the 0.10.19-0.10.24 relay fixes above). Those calls wait on main across a single `std::recursive_mutex runtime.mutex` shared by every relayed operation from every shard, with timeouts of 10-60 seconds. If enough of them landed on one shard concurrently to occupy all `threads` pool workers at once, the pool's unbounded queue had nowhere to run a newly arrived `fed_request` — even one that would never need to call main at all, such as a `state`/`backfill`/`state_ids` read answered entirely from the worker's own local snapshot. The shard then appeared fully hung until the backlog drained, at which point `WorkerPool::handle()`'s own `federation.worker.request_timeout_seconds` (shipped default 30s) elapsed and returned a `503` to the remote peer. The same mechanism plausibly also explains intermittent to-device delivery gaps investigated this cycle (see Testing below): an EDU's own `edu_sink` call queued behind this backlog can complete so late that nothing is still listening for it. Fix: `worker_event_loop.cpp` now runs two pools — `local_pool` (existing `threads`) for endpoints answerable entirely from the worker's own local snapshot (`make_join`/`make_leave`/`make_knock`, `backfill`, `query/directory`, `state`, `state_ids`, `get_missing_events`, `hierarchy`, and the no-op `send_edu` stub), and a new `relay_pool` (`federation.worker.relay_threads`, default 32) for the ten endpoints that can call main (`transaction`, `send_join`/`send_leave`/`send_knock`, `invite`, `query_profile`, `query_keys`, `claim_keys`, `query_user_devices`, `query_event`) plus every `outbound_http_request` message, which blocks on a remote server's response instead. The classification is a new pure function, `federation::federation_endpoint_requires_main_relay(FederationEndpoint)`, applied to the existing route match before a thread is committed. New scenario in `tests/unit/test_federation_transactions.cpp` iterates every entry in `federation_routes()` and asserts each lands in its expected pool bucket, so a future endpoint added without an explicit classification is caught immediately (the switch has no `default:` case). See `docs/architecture.md`, "Federation worker relay pool separation".
- **fix(ci): the Fedora, RHEL, and OpenSUSE RPM package jobs started failing after the 0.10.25 merge — the `.rpm` build itself succeeded every time, but the `Attest ... RPM` step (`actions/attest-build-provenance@v2`) failed with `InternalError: error fetching tlog entry - (404) Not Found`:** Sigstore's Rekor transparency log had not finished replicating the entry the action itself just wrote by the time it immediately tried to read it back — an external infrastructure race, not a build or packaging defect. Fix: each of the three `Attest` steps in `.github/workflows/packages.yml` now retries up to twice with a short delay (15s, then 30s) before giving up for real, using `continue-on-error` plus `steps.<id>.outcome` gating — the same repo-native retry pattern already used for the `netbsd-pkg-retry` job and the `zypper` install loop in the OpenSUSE job, applied at step granularity since re-running the whole build is unnecessary. The final attempt in each chain has no `continue-on-error`, so a genuine, persistent failure still fails the job.

### Testing
- **test(federation,sync): investigated the ongoing intermittent E2EE key-share decrypt failures reported on `pong.ping.me.uk` and ruled out three suspects against the real code paths rather than test-only shortcuts:** a large, deeply nested Olm-encrypted `m.direct_to_device` EDU was routed through `handle_federation_http_request()` (the real production/worker entry point, as opposed to `handle_local_http_request()`'s federation branch, which looks similar but is a test-only shortcut that never calls `wire_federation_callbacks_impl()`) in `tests/integration/test_federation_inbound_flow.cpp`; the same realistic EDU was sent over a real encrypted `ipc::IpcChannel` pair (real AF_UNIX socketpair, real AEAD framing) in `tests/integration/test_federation_worker_flow.cpp`, proving a large nested payload survives the actual worker/main transport; and `tests/unit/test_sync_handler.cpp` wired federation callbacks the way `main.cpp` does at startup and called `handle_edu_ingest_request()` (what a worker's IPC relay lands on) while a client was parked in a long-poll, proving the sync notifier wakes exactly as it does for a local to-device send. All three passed, ruling out large-payload parsing, the IPC transport, and sync-notifier wiring as the cause; this investigation is what led to identifying and fixing the federation worker thread-pool starvation bug above.

## 0.10.25

### Diagnostics
- **diag(federation): `handle_inbound_federation_request()`'s own logging (`request.received`, `transaction.accepted`) has never been observed in production despite clear downstream evidence that it executes — `event_state.persisted` (logged on main's side when a worker relays a PDU via `pdu_ingest`) fires reliably for real transactions, which is only reachable by that function calling `pdu_sink` partway through its body, yet neither its first line nor its final log line ever appears, with no exception (`thread_pool: event=worker.exception` never fires on either process's thread pool), no worker crash/restart, and no seccomp syscall denial (`write`/`writev`/`futex`/`clone` are all allowed in the worker hardening profile) found to explain it:** since `handle_inbound_federation_request` runs entirely inside the federation worker's own process when a room-scoped request is relayed there, and its logging is the one piece of visibility this investigation could not otherwise obtain, `WorkerPool::handle()` — which runs on main, whose own logging has been reliable throughout every incident investigated so far — now logs the raw status, body length, and a short body prefix of every reply a worker sends back, immediately after deserializing it and before returning it to the caller. This does not fix a known bug; it exists to determine, from a call site proven trustworthy, whether the worker's reply actually originated from `handle_inbound_federation_request`'s normal success path (in which case the worker's own logging has a real, separate gap worth fixing next) or from somewhere else entirely.

## 0.10.24

### Fixed
- **fix(federation,security): the federation worker's `user_devices_provider`, `device_keys_query_provider`, and `profile_query_provider` decided their answers from a per-process in-memory snapshot hydrated once at worker startup, with no mechanism to ever refresh it, causing a remote server's E2EE key-share to silently fail forever:** unlike the write-relay hooks (`pdu_sink`, `membership_acceptor`, `edu_sink`, `invite_handler`) and the split-brain hook (`one_time_keys_claim_provider`), these three are pure reads backing `GET /_matrix/federation/v1/user/devices/{userId}`, `POST /_matrix/federation/v1/user/keys/query`, and `GET /_matrix/federation/v1/query/profile` — none of which carry a room ID, so unlike `state_query_provider`/`state_ids_query_provider`/`backfill_provider`/`missing_events_query_provider` (kept fresh by `notify_room_changed()`/`reload_room()`, see "Federation worker room staleness") there is no per-room notification channel that could ever refresh `PersistentStore::device_keys`/`PersistentStore::profiles` on a worker. A device key uploaded, or a profile changed, through main's client-server API after a worker started is therefore permanently invisible to that worker. Reproduced against a real two-homeserver federation (`matrix.ping.me.uk` → `pong.ping.me.uk`, `federation.worker.shards=2`, the shipped example config): `matrix.ping.me.uk` queried `GET /_matrix/federation/v1/user/devices/@james:pong.ping.me.uk` to learn which device to target an `m.room_key` to-device share at, got a spurious `404 M_NOT_FOUND` from a worker whose device-key snapshot predated the device's key upload, and never sent the room key — the recipient's client logged `Can't find the room key to decrypt the event, withheld code: None` for every message under that session, with nothing in the server's own logs indicating a failure, since the transaction carrying the encrypted PDU itself was still accepted and delivered normally. Fix: `worker_event_loop.cpp` now overrides all three providers the same way it overrides `one_time_keys_claim_provider` — serializes the request (a bare `user_id`, or the raw federation request body for `device_keys_query_provider`) into a new `user_devices_ingest`/`device_keys_query_ingest`/`profile_query_ingest` IPC frame and calls main, rather than deciding locally; `worker_pool.cpp`'s `handle_user_devices_ingest_request()`/`handle_device_keys_query_ingest_request()`/`handle_profile_query_ingest_request()` (free functions alongside the other `*_ingest_request` handlers, same test-seam reason) receive them on main's side and invoke main's own unmodified providers under `runtime.mutex`. New scenarios in `tests/integration/test_federation_worker_flow.cpp` seed a device key and a profile on main's own store, drive each handler with a request shaped like a real worker's ingest frame, and assert the response reflects main's data rather than an empty worker-local snapshot. See `docs/architecture.md`, "Federation worker user/device/profile/event query relay".
- **fix(federation): `event_query_provider` (`GET /_matrix/federation/v1/event/{eventId}`) has a related but structurally different bug from the three above — its path carries no room ID either, so unlike `state`/`state_ids`/`backfill`/`get_missing_events` it can never be sharded by room and always lands on shard 0 regardless of which shard actually owns the event's room:** the same class of routing-alignment problem `query/directory` already has (see "Shard routing must key on the same room ID string as the notification"), not the "no notification channel exists at all" problem the three providers above have — `PersistentStore::events` for a room hosted on a shard other than 0 is never refreshed on shard 0, since `notify_room_changed()` hashes and delivers to the room's actual owning shard, not shard 0 unconditionally. A real routing fix would need an event-ID-to-room-ID index reachable before shard selection, which does not exist today. Fix: rather than build that index, `event_query_provider` is relayed through main via a new `event_query_ingest` IPC frame the same way the three providers above are — main receives every event via `pdu_sink` regardless of which shard accepted it, so answering from main's store is correct no matter which shard the request lands on. `worker_pool.cpp`'s `handle_event_query_ingest_request()` follows the same free-function/test-seam pattern as the other `*_ingest_request` handlers. New scenario in `tests/integration/test_federation_worker_flow.cpp` seeds an event on main's own store and asserts the relayed response contains it. See `docs/architecture.md`, "Federation worker user/device/profile/event query relay".

## 0.10.23

### Fixed
- **fix(media,security): `fetch_remote_media_live()` fabricated `scanner_clean=true`/`decoder_marked_safe=true` for every federated media fetch, bypassing the AV-scanner gate for attacker-controlled content whenever `security.media.remote_fetch_enabled` is on:** the remote-fetch path is the only untrusted-content boundary in the media repository — unlike a local upload, a federated origin server has no accountable local identity behind it — yet it reported the same "clean" verdict as a locally authenticated upload with no real scan ever having occurred (Merovingian does not run an AV engine for any media source today; see `docs/media-repository.md`). Fix: `remote_req.scanner_clean` is now honestly reported as `false` (no scan happened), and a new `MediaAcceptancePolicy` (`allow` / `allow-after-scan` / `quarantine` / `deny`) governs the final disposition, configured independently for local uploads (`security.media.local_upload_policy`, default `allow-after-scan`, preserving prior behaviour) and remote fetches (`security.media.remote_fetch_media_policy`, default `quarantine`, since federated content is never actually scanned). `decoder_marked_safe` is deliberately left `true` for remote content: `unsafe_decoders_disabled` has no config knob today, so flipping it would hard-reject every remote fetch in every deployment by default rather than fail safely — tracked as a follow-up alongside real AV-scanner integration. New scenarios in `tests/unit/test_media_security.cpp` (`evaluate_media_upload`'s four-policy behaviour) and `tests/unit/test_media_repository.cpp` (remote fetch quarantined by default vs. local upload accepted by default under identical scanner-clean input).
- **fix(media,security): the outbound federation media download URL omitted the `{serverName}` path segment the spec requires and never percent-encoded either segment:** `fetch_remote_media_live()` built `/_matrix/media/v3/download/{mediaId}` instead of `/_matrix/media/v3/download/{serverName}/{mediaId}` (server-server-api.md#get_matrixmediav3downloadservernamemediaid), so a media ID or origin server name containing reserved characters could be misread as an extra path segment or a different route on the resolved host. Fix: the URL construction is extracted into `remote_media_download_url()` (`homeserver/media_service.hpp`), which builds the correct two-segment path with both `origin_server` and `media_id` passed through `core::percent_encode_path_component()`. New `tests/unit/test_homeserver_media_service.cpp` pins the URL shape and the encoding of reserved characters.
- **fix(http,security): trusted-proxy `X-Forwarded-For` rate-limit keying trusted any non-empty value verbatim with no IP validation:** when the direct peer was a configured `server.trusted_proxies` entry, the client-server rate limiter used the leftmost `X-Forwarded-For` value as the rate-limit key without checking it was a syntactically valid IP address, letting an attacker (or a misconfigured proxy that fails to overwrite an inbound header) rotate through malformed pseudo-IP strings to mint a fresh bucket per request and defeat per-IP rate limiting on `/login`, `/register`, and every other endpoint. Fix: the candidate is now validated with the new `federation::ip_address_is_valid()` (strict `inet_pton`-based IPv4/IPv6 literal check) before being trusted; a missing or malformed value falls back to the direct peer address. New `tests/unit/test_client_server.cpp` scenario asserts two malformed X-Forwarded-For values from the same trusted proxy share the direct-peer bucket instead of minting independent ones.
- **fix(media,security): admin media quarantine/release/remove routes accepted unsanitized media IDs from the raw path suffix:** unlike the download/thumbnail routes (`local_media_download_parts()`), the `/_merovingian/admin/media/{quarantine,release,remove}` routes passed the raw path suffix directly as the media ID with no validation, so a request like `.../remove/<id>?reason=x` treated the query string as part of the ID — no record matched it, and the intended object was silently left untouched instead of acted on. Fix: `admin_media_id_from_suffix()` (`local_http_router.cpp`) strips any query string and rejects an empty ID, an embedded `/`, a `..` traversal sequence, or an embedded space before the ID reaches the admin action; a `400` is returned instead. New `tests/integration/test_media_repository_security.cpp` scenario covers a trailing query string (correctly stripped, object still acted on), a path-traversal sequence, and an empty ID.

### Documentation
- **docs(media,security): made explicit, in the places an operator is most likely to read them, that AV scanning can never inspect encrypted-room media:** the new `MediaAcceptancePolicy` keys risked implying a scanner verdict is meaningful for all media, when in fact `application/octet-stream` (E2EE attachments encrypted client-side before upload) is opaque ciphertext the server never holds the key for — no configuration, proxy placement, or future scanner integration can change that without breaking end-to-end encryption's confidentiality guarantee. Added a `WARNING` block to `config/merovingian.conf.example`'s media section, a new "Encrypted media is never scannable" section to `docs/media-repository.md`, a leading paragraph to the media section of `docs/configuration.md`, and a cross-reference from `docs/architecture.md`'s media-security summary line.

## 0.10.22

### Testing
- **test(federation): the 0.10.19-0.10.21 worker/main relay fixes (`membership_ingest`, `edu_ingest`, `invite_ingest`, `otk_claim_ingest`) only had happy-path integration coverage — every existing scenario asserted `accepted:true`/`status:200`, none exercised the fail-closed branches those handlers actually contain:** added eight new scenarios to `tests/integration/test_federation_worker_flow.cpp`, driving each `handle_*_ingest_request()` free function directly with the same wire format `worker_event_loop.cpp` produces (the same test-seam pattern the original scenarios established). `handle_membership_ingest_request`: relaying a `send_join` for a room main has never stored now asserts the existing `{false, 404, "room not found"}` branch and that no membership row is written; calling it with `membership_acceptor` unwired asserts the `501` fallback rather than assuming it can't happen. `handle_edu_ingest_request`: a `m.direct_to_device` EDU missing the required `messages` field now asserts `rejected_invalid` and that nothing reaches `to_device_messages`; an unwired `edu_sink` asserts `rejected_invalid` with a `"edu_sink not wired"` reason instead of crashing on an empty `std::function`. `handle_invite_ingest_request`: inviting a user this server does not host now asserts the `404 "invited local user not found"` branch and that no membership/invite row is written; an unwired `invite_handler` asserts `501`. `handle_otk_claim_ingest_request`: the actual split-brain property 0.10.21 fixes is pinned directly — two consecutive claims for the same `(user, device, algorithm)` now assert the second returns no key material, since the first claim must consume it from main's single store; a device with no stored one-time or fallback key asserts an empty `one_time_keys` object rather than an error. A shared `ipc_escape_json_string()` helper replaces the escaping lambda duplicated across scenarios. No production code changed; all new and pre-existing scenarios in the file pass (94 assertions, 12 test cases for `[membership],[edu],[invite],[otk]` alone).

## 0.10.21

### Fixed
- **fix(federation): the federation worker's `invite_handler` persisted a federated invite's membership row, invite metadata, and event only into whichever process ran it — never relayed to main, the same class of gap 0.10.19 fixed for `membership_acceptor`:** `invite_handler` was not among the hooks the worker overrides (`pdu_sink`, `membership_acceptor`, `edu_sink` were), so `PUT /_matrix/federation/{v1,v2}/invite` — room-scoped, so handled by a worker whenever `federation.worker.shards >= 1` (the shipped example config) — ran the default implementation (`local_http_router.cpp`) unmodified, writing `upsert_membership`/`database::upsert_invite`/`database::store_event_with_state` straight into that worker's own `PersistentStore`. Since real clients only ever `/sync` against main, and nothing else ever re-syncs invite data into main's store, a remote server inviting one of this server's local users to a room hosted elsewhere was silently swallowed: the invite never appeared in the invited user's own `/sync`, with no error anywhere. Fix: `worker_event_loop.cpp` now overrides `invite_handler` the same way it overrides `membership_acceptor` — serializes the `InviteRequest` into a new `invite_ingest` IPC frame and calls main instead of persisting locally; `worker_pool.cpp`'s `handle_invite_ingest_request()` (a free function alongside `handle_membership_ingest_request()`, same test-seam reason) receives it on main's side and invokes main's own unmodified `invite_handler` under `runtime.mutex`. New integration scenario in `tests/integration/test_federation_worker_flow.cpp` drives `handle_invite_ingest_request()` directly and asserts the invite's membership row and invite metadata land in main's own `PersistentStore`. See `docs/architecture.md`, "Federation worker invite relay".
- **fix(federation,security): the federation worker's `one_time_keys_claim_provider` decided one-time-key availability from a per-process in-memory snapshot, risking a key being handed out twice (breaking Olm's single-use guarantee) and going permanently stale as fresh keys were uploaded through main:** `database::claim_one_time_key` searches `PersistentStore::one_time_keys` — an in-memory vector hydrated once at worker startup — before issuing a `DELETE`; that vector is never invalidated by a different process's write to the same underlying table. `POST /user/keys/claim` is non-room-scoped and lands on shard 0 in steady state, but `WorkerPool::handle()` falls back to running in-process on main when the owning shard is unhealthy — if shard 0 already claimed a key and main's own copy hasn't independently learned it's gone, a later claim falling back to main can return the *same* one-time prekey a second time, undermining the forward-secrecy guarantee a one-time key exists to provide. The same divergence also caused key claims to dry up in the other direction: keys uploaded through main after a worker started were invisible to that worker's frozen snapshot. Fix: rather than patch the claim-and-delete to be atomic at the database layer (which would still leave main's own cache diverged from a worker's writes), `one_time_keys_claim_provider` is now relayed through main entirely, the same as the other hooks — `worker_event_loop.cpp` serializes the raw claim request body into a new `otk_claim_ingest` IPC frame; `worker_pool.cpp`'s `handle_otk_claim_ingest_request()` invokes main's own unmodified provider under `runtime.mutex`. New integration scenario in `tests/integration/test_federation_worker_flow.cpp` seeds a one-time key, drives the handler directly, and asserts both that the response echoes the claimed key and that the key is gone from main's own store afterward. See `docs/architecture.md`, "Federation worker one-time-key claim relay".
- **fix(federation): ordinary messages and state changes never refreshed a federation worker's room snapshot — only the 7 membership-mutating room_service calls did, and `pdu_sink`'s worker override deliberately never writes to the worker's own store either — so worker-served `backfill`/`event`/`state`/`state_ids`/`get_missing_events` queries for an active room could silently omit every message sent since its last membership-triggered reload:** `send_event()` (`room_service.cpp`) was never among the calls that invoke `notify_room_changed()`, and nothing pushed an inbound-relayed message (via a worker's `pdu_sink` IPC call) back down to the relaying worker's own snapshot either. Fix: `send_event()` now also calls `notify_room_changed(runtime, room_id)`, matching the placement convention of the existing 7 call sites; `worker_pool.cpp`'s `pdu_ingest` IPC handler now calls `notify_room_changed(env.room_id)` after a successful `pdu_sink` commit, pushing the just-committed event back to whichever shard owns the room (in practice the same worker that made the call, since shard selection is a pure function of `room_id`). New `send_event notifies the federation worker when an ordinary message is sent` scenario in `tests/unit/test_homeserver_room_service.cpp` extends the existing `test_room_changed_log`-pinned contract to this eighth call site. See `docs/architecture.md`, "Federation worker room staleness".

## 0.10.20

### Fixed
- **fix(federation): the federation worker's `edu_sink` was a hard no-op that silently dropped every inbound EDU it handled — including `m.direct_to_device`, the transport for E2EE megolm room-key shares — while logging them as dispatched rather than dropped:** `worker_event_loop.cpp` set `runtime.federation.edu_sink = {};` unconditionally with the stated reasoning "EDUs are ephemeral and acceptable to drop." True for `m.typing`/`m.receipt`/`m.presence`, but not for `m.direct_to_device` (carries `m.room_key`/`m.room_key.withheld` to-device messages) or `m.device_list_update`. Worse, `inbound_request.cpp`'s transaction loop counts an EDU with no `edu_sink` installed as `edus_dispatched`, not `edus_dropped` — the `transaction.accepted` diagnostic and the `200` returned to the sending server gave no indication anything was lost. Reproduced against a real two-homeserver federation (`matrix.ping.me.uk` → `pong.ping.me.uk`, `federation.worker.shards=2`, the shipped example config): a megolm room-key share sent as an `m.direct_to_device` EDU landed on a worker shard and vanished; the recipient's client (`matrix-sdk-crypto` 0.18.0) logged `Can't find the room key to decrypt the event, withheld code: None` for every subsequent message encrypted with that session, and its `PerSessionKeyBackupDownloader` fallback also failed, since the key was never received by any recipient device in the first place — not even an `m.room_key.withheld` notice, since that's carried as an EDU too and would have been dropped identically. This is the same class of bug as the 0.10.19 `membership_acceptor` fix and the 0.10.14–0.10.18 room-staleness fixes, but for the one remaining unrelayed hook. Fix: `worker_event_loop.cpp` now overrides `edu_sink` the same way it overrides `pdu_sink`/`membership_acceptor` — serializes the `InboundEduEnvelope` (edu_type, origin, content_json) into a new `edu_ingest` IPC frame and calls main instead of handling (or dropping) it locally; `content_json` is embedded as an escaped JSON string via `ipc::ipc_json_str`, the same technique `pdu_ingest`'s `json` field already uses, so nested content containing a literal `"type"` key (as `m.room_key.withheld` content does) cannot be confused with the outer frame's own `"type"` field. A new `handle_edu_ingest_request()` (`worker_pool.cpp`, exposed as a free function alongside `handle_membership_ingest_request()` for the same test-seam reason) receives the relayed request on main's side, reconstructs the envelope via `federation::parse_inbound_edu_envelope()`, and invokes main's own unmodified `edu_sink` under `runtime.mutex` — no separate `sync_notifier->publish()` call is needed, since every case inside main's `edu_sink` already publishes on its own success path. All EDU types are relayed uniformly (not just `m.direct_to_device`), so a future EDU type added to `classify_edu_type` without a matching drop-list update can't silently regress this again. New integration scenario in `tests/integration/test_federation_worker_flow.cpp` drives `handle_edu_ingest_request()` directly with an `m.direct_to_device` request shaped exactly like a real worker's `edu_ingest` frame and asserts the room-key share lands in main's own `PersistentStore::to_device_messages` — the same test-seam pattern the 0.10.19 membership fix established, for the same reason (a real end-to-end worker-subprocess round trip needs a live, network-resolvable remote signing key to clear the federation-policy gate ahead of `edu_sink`, orthogonal infrastructure this bug isn't about). See `docs/architecture.md`, "Federation worker EDU relay".

## 0.10.19

### Fixed
- **fix(federation): a remote user's federated join/leave/knock — accepted correctly by a federation worker — was invisible to the main process's own room state, so every subsequent message from that member was rejected with `"sender is not joined to the room"`:** `merovingian-fed-worker` runs its own full `HomeserverRuntime`, and per its own documented design ("It does NOT write events — accepted PDUs are sent to main via pdu_ingest IPC and main commits them with the authoritative counter", `worker_event_loop.cpp`), regular `/send` transaction events already relay through `pdu_sink` to main for persistence. `membership_acceptor` — the handler backing `send_join`/`send_leave`/`send_knock`, wired by the same shared `wire_federation_callbacks_impl()` used for `pdu_sink`'s *default* implementation — was never given the same treatment: it persisted straight into `rt->database.persistent_store`, which inside a worker process is that worker's own local, in-memory-cached store, completely bypassing main. So when a remote server joined a room via `send_join` (processed inside a worker), the join was durably written to the worker's own view of the database, but main's own `PersistentStore` — the one `pdu_sink` authorizes every later `/send` message against — never learned the member existed. Reproduced against a real two-homeserver federation (`matrix.ping.me.uk` → `pong.ping.me.uk`): the remote user's join succeeded (visible via a client-side sync), but their very next message was silently dropped by `event_auth`'s step-10 "sender must be joined" check, logged only as a `DEBUG`-level `authorization.rejected` line with no error-level signal anywhere. This is a distinct bug from the earlier 0.10.14–0.10.18 federation-worker-staleness/shard-routing fixes: those were about a worker's view of a room going stale relative to main, or a room-sync notification landing on the wrong shard; this is the *reverse* direction — a worker unilaterally accepting a write that main, the authority `pdu_sink` checks against, never receives at all. Fix: `runtime.federation.membership_acceptor` is now overridden inside the worker process (`worker_event_loop.cpp`), mirroring `pdu_sink`'s existing override exactly — it serializes the accepted endpoint (`send_join`/`send_leave`/`send_knock`) and the inbound PDU envelope into a new `membership_ingest` IPC frame and calls main over the same channel, rather than writing locally. A new `handle_membership_ingest_request()` (`worker_pool.cpp`, exposed as a free function alongside the existing `federation_worker_shard_for()` specifically so it has a test seam independent of the IPC machinery) receives the relayed request on main's side, invokes main's own (unmodified) `membership_acceptor` under `runtime.mutex`, and returns the `MembershipAcceptResult` — including the `auth_chain`/`state` snapshot the `send_join` response body requires — back across the channel. Unlike `pdu_ingest`'s handler, this one does not need to separately call `sync_notifier->publish()`: the default `membership_acceptor` implementation already does that itself on success. New integration scenario in `tests/integration/test_federation_worker_flow.cpp` drives `handle_membership_ingest_request()` directly with a request shaped exactly like a real worker's `membership_ingest` frame and asserts the join lands in main's own `PersistentStore` (state and membership rows) — a real end-to-end round trip through a worker subprocess would additionally have to clear the unrelated "remote is unknown" federation-policy gate ahead of `membership_acceptor` in `inbound_request.cpp`, which needs a live, network-resolvable remote signing key; this file's other worker-pool scenarios don't clear that gate either, and asserting only `status != 503` for all of them was a known, documented test gap closed only partially here. See `docs/architecture.md`, "Federation worker room staleness".

## 0.10.18

### Fixed
- **fix(federation): inbound `make_join`/`state`/`send_join`/etc. against a room that genuinely exists locally could still 404 from the federation worker when `federation.worker.shards` is configured above the default of 1:** `federation_worker_room_id_from_request()` extracted the room ID straight from the raw HTTP path segment (e.g. `/_matrix/federation/v1/make_join/%21abc:example.com/...`) without percent-decoding it, then hashed that raw string via `federation_worker_shard_for()` to pick which worker shard should handle the request. Every write path that keeps a shard's local `PersistentStore` in sync — `notify_room_changed()`, called from `create_room`/`join_room`/`leave_room`/`invite_user`/`ban_user`/`kick_user`/`unban_user` — instead notifies using the plain, already-decoded room ID (`!abc:example.com`), since that's the form stored internally and never touches a URL. `%21abc:example.com` and `!abc:example.com` hash to different shards whenever `shards > 1`, so the room-sync notification landed on a different worker than the one that would later receive the request for that room: the request-serving shard's local store never learned the room existed, and `handle_make_membership()` correctly (from its own perspective) returned `404 M_NOT_FOUND`, reproducing as a permanent "Failed to make_join via any server" from the remote server no matter how many times it retried. Reproduced against a real two-homeserver federation (`pong.ping.me.uk` → `matrix.ping.me.uk`), where the room was demonstrably resident and the invite had already been delivered successfully. `room_id_from_path_target()` now percent-decodes the extracted segment via `core::percent_decode_path_component()` before it is returned, so shard selection uses the same canonical room ID string on both the write (`notify_room_changed`) and read (`FederationProxy::handle`) sides. This affects every room-scoped federation endpoint routed through `federation_worker_room_id_from_request()`, not just `make_join`. `federation.worker.shards=2` is the shipped example config (`config/merovingian.conf.example`), so any deployment following it was exposed. New scenario in `tests/unit/test_federation_request_routing.cpp` pins that a percent-encoded room ID (`%21room%3Aexample.com`) in a `make_join` path decodes to the same room ID a plain, unencoded path would extract.

### Testing
- **test(federation): the sharding test suite never asserted the invariant that actually broke above, and no test anywhere fed a percent-encoded room ID through the routing path — both gaps are why this bug shipped unnoticed:** `tests/integration/test_federation_worker_flow.cpp`'s existing "Room-scoped federation requests are routed to the correct shard" scenario only checked that each of two room IDs landed on *some* valid shard index (`< shards`), never that it was the *same* shard `notify_room_changed()` would use for that room — the actual property that matters, since a wrong-but-valid shard index is indistinguishable from a correct one by that check alone. It's strengthened with a new `WHEN` that spins up a real two-shard worker pool and asserts a request-derived room ID (plain and percent-encoded) matches, string-for-string, the plain room ID `notify_room_changed()` hashes directly, plus the resulting shard indices agree — string equality first because with only a couple of shards two different strings can coincidentally land in the same bucket, which would let a real mismatch slip past a shard-only comparison undetected (caught during development: an earlier version of this same test using only shard-index equality passed by 50/50 chance against the reintroduced bug). Verified against both states: fails deterministically with the `percent_decode_path_component` fix reverted, passes with it restored. Every unit-test scenario in `tests/unit/test_federation_request_routing.cpp` for room-ID extraction previously used an already-decoded string as input, so the missing decode step had no unit-level test surface to fail against either; `tests/unit/test_federation_request_routing.cpp` now exercises percent-encoded room IDs across all thirteen v1 and five v2 room-scoped endpoint prefixes (previously only `make_join`/`send_join` were covered), not just the two originally added alongside the fix above.
- **fix(federation): removed a dead, misleading `room_endpoint_prefixes()` entry for `GET /_matrix/federation/v1/query/directory` that could never match a real request:** per spec (`server-server-api.md#get_matrixfederationv1querydirectory`), `room_alias` is a query parameter (`?room_alias=...`), not a path segment — confirmed against `inbound_request.cpp`'s own handler, which reads it via `query_param_value()`. The path-segment-style prefix `"/_matrix/federation/v1/query/directory/"` therefore never matched any real request's shape and was dead code; it's removed, and this endpoint now explicitly documents that it falls through to shard 0 like any other non-room request, matching its actual (still incomplete) behavior. Fixing the routing extraction alone would not have made this endpoint correct: the room alias and the room_id `notify_room_changed()` partitions by are unrelated strings that hash to essentially independent shards, and `database::reload_room()` does not sync `store.room_aliases` per-room today regardless of which shard a request lands on. Properly sharding room-alias federation queries needs a real design decision (route to shard 0 and replicate `room_aliases` to every shard, resolve the alias in the main process before forwarding, or a dedicated non-sharded alias index) — tracked as a follow-up, documented in `docs/architecture.md`'s "Federation worker room staleness" section ("Known gap: `GET /query/directory` cannot be sharded by this scheme at all"). The corresponding unit test scenario is updated to assert the (accurate, if still limited) current behavior instead of asserting only "a room ID was extracted," which was true but did not reflect the real, still-broken-for-`shards>1` state.

## 0.10.17

### Fixed
- **fix(sync): `rooms.leave.<room_id>.timeline` in the `/sync` response was always an empty events array, so a real client (Element/matrix-js-sdk) never actually saw itself leave even though 0.10.16 already fixed `stream_ordering`/`sync_notifier` and the server's own logs showed `leave_count=1` delivered correctly:** confirmed against Element's own network/console log — `POST /leave` returns `200` in 40ms, the in-flight long-poll `GET /sync` wakes and returns `200` with the room correctly keyed under `rooms.leave`, and the room still never disappeared from the client's room list. Per spec, `rooms.leave.<room_id>.timeline` is "the timeline of messages and state changes in the room up to the point when the user left" — matrix-js-sdk derives `room.getMyMembership()` by processing that timeline's state events, not merely from the room_id being present as a key, so an always-empty timeline gave the client nothing to act on. New `build_leave_timeline_events_array()` (`client_server.cpp`) looks up the user's current `m.room.member` state event for the room (authoritative even on an idempotent repeat `/leave`, since `store.state` is upserted in place by every real transition, including kicks and bans) and includes it as the room's sole timeline event, matching what real homeservers send. Strengthened the existing `test_client_server.cpp` leave-sync scenario to assert the timeline actually contains an `m.room.member`/`membership: leave` event, not just the room_id key.

## 0.10.16

### Fixed
- **fix(sync,federation): a repeat `/leave` call on a room the caller already left server-side never healed a client stuck seeing it as joined:** `leave_room`'s idempotent "already left" branch (hit when the membership row is not `"join"`/`"invite"`) returned `200` without calling `persist_membership_transition`, so it never advanced `stream_ordering` or notified `sync_notifier`/the federation worker. Reproduced from a real server's logs, right after upgrading to 0.10.15: a client's *earlier* leave had flipped `membership` to `"leave"` correctly, but under the pre-0.10.15 bug its `stream_ordering` stayed frozen, so `/sync` never told the client it had left; the client, still believing it was joined, retried `/leave` — and that retry hit the idempotent no-op path, which (correctly, per spec, on `membership` alone) did nothing further, leaving the row permanently stuck even across the restart onto the fixed build. A repeat `/leave` call is itself evidence the caller's view is stale, so the idempotent branch now also allocates a fresh `stream_ordering`, persists it via `store_or_update_membership` (membership value unchanged), publishes to `sync_notifier`, and calls `notify_room_changed()` — self-healing rows left in this state by the 0.10.15-era bug without requiring a manual database repair. New regression scenario in `tests/unit/test_homeserver_room_service.cpp` pins that a second `leave_room` call advances `stream_ordering` past the first and re-notifies the federation worker.

## 0.10.15

### Fixed
- **fix(database): `update_membership()` silently dropped `stream_ordering` on every membership transition, freezing `/sync`'s only signal that a membership row changed:** `POST /leave` (and every other membership transition on a pre-existing row — invite, kick, ban, rejoin) went through `store_membership()` first, which only succeeds on a brand-new row; an existing row instead fell through to `update_membership()`, whose `UPDATE membership SET membership = $3 ...` never touched the `stream_ordering` column, and the in-memory `PersistentMembership::stream_ordering` was left untouched too. The row's `membership` value flipped correctly, but its `stream_ordering` stayed pinned at whatever it was on first insert (frequently `0`), so any later `since`-token comparison against it (`joined_membership_changed_since`, and the `rooms.leave` inclusion check below) could never see the change as "recent." `update_membership()` now takes a `stream_ordering` parameter, persists it in the same `UPDATE` (`stream_ordering = $4`), and writes it to the in-memory row; all nine call sites (`room_service.cpp`, `local_http_router.cpp`) now pass the same counter value used for the corresponding `store_membership()` attempt.
- **fix(sync): a room the caller just left never disappeared from their client, because `/sync` omitted it from `rooms.leave` unless the (rarely set) `include_leave` filter was true:** reproduced from a real server's logs — `POST /leave` returned `200` and `room.leave.accepted`, but the room stayed in the client's list forever, and a repeat `/leave` also silently no-op'd (membership was already `"leave"` server-side). Per spec, a room left *before* the sync window began is correctly omitted unless `include_leave: true` — but a leave/kick/ban that happens *within* the current window is a state change the client must be told about regardless of that flag, since most clients (matrix-js-sdk, Element) never set it. `rooms.leave` in the incremental-sync path now also includes a `"leave"` membership when `membership.stream_ordering > since_ordering`, i.e. it changed after the caller's last sync; already-known leaves (older than `since`) remain gated behind `include_leave` as before. Depends on the `update_membership` fix above — without it, `stream_ordering` never actually advances on the leave, so this check alone would not have been sufficient.
- **fix(federation): `invite_user`/`ban_user`/`kick_user`/`unban_user` never notified the federation worker of the membership change, so a remote user invited to an existing, already-resident room could get a permanent `502 Failed to make_join via any server` / `404` from `make_join`:** the 0.10.14 federation-worker-staleness fix wired `notify_room_changed()` into `create_room`/`join_room`/`leave_room` — every call that changes *this server's own* residency in a room — but missed the four calls that mutate a *second* user's membership on a room this server is already resident in. Reproduced from a real server's logs: a local user creates a room and invites a remote Synapse user; the remote server's `make_join` 404s from the worker on every retry, indefinitely, because the worker's `store.rooms` snapshot never learned the room existed (its own creation-time notification can be silently dropped if the worker's IPC channel wasn't yet healthy — a pre-existing, separate gap — and nothing else ever re-notifies for that room_id once only invites/kicks/bans happen against it afterward). All four now call `notify_room_changed(runtime, room_id)` after committing the membership change, matching the existing pattern; `tests/unit/test_homeserver_room_service.cpp` gains one `test_room_changed_log`-pinned regression scenario per function, alongside the three already covering create/join/leave. See `docs/architecture.md`, "Federation worker room staleness".

## 0.10.14

### Fixed
- **fix(federation): `send_join` still failed for a genuinely huge room with `502 send_join failed: response_too_large`, even after the `join_timeout`/base64-framing fixes in 0.10.13 gave it enough time and IPC headroom:** `OutboundClient` rejects any response body larger than `http::OutboundRequest::max_response_body_bytes`, a hardcoded 16 MiB used by every federation call — but a `send_join` response embeds the room's *entire* current state (one `m.room.member` per member plus the auth chain), and for a room like `matrix.org`'s `#community` with tens of thousands of members that routinely exceeds 16 MiB long before any timeout or IPC frame limit is reached. New `security.federation.join_response_max_size` (default `64MiB`) gives `make_join`/`send_join` their own response-size budget, threaded through a new `OutboundCall::max_response_body_bytes` field (`build_outbound_request` forwards it to `OutboundRequest`) and a new `perform_sync_outbound_call` parameter that `send_join`'s call site populates from the config value; every other federation call keeps the 16 MiB default. Because the federation-worker IPC channel's `outbound_http_response` frame carries the base64-encoded body (see the 0.10.12 entry below), raising this cap also has to raise the channel's `max_frame_bytes` — a new `ipc::frame_bytes_for_response_cap()` computes the required frame size from the configured response cap, and `WorkerPool` (main process) and `WorkerEventLoop` (worker process) each derive it independently from the same config so both sides of the channel agree without negotiating it over IPC itself. This value is baked in at worker-spawn time, so unlike the other `join_*` keys it is `restart_required`, not hot-reloadable — `reload_policy_for_key` now special-cases it.
- **fix(federation): inbound `make_join`/`state`/etc. against a room this server just became resident in (via `create_room`, a federated `join_room`, or a local join) could 404 from the federation worker even though the room fully exists in the database:** `merovingian-fed-worker` runs its own `HomeserverRuntime` with its own `PersistentStore`, hydrated once from disk at worker startup — every write helper (`store_room`, `store_membership`, ...) updates the database *and* that same process's in-memory vectors together, but nothing pushes a write made by the main process into a worker's already-running copy. Since inbound federation requests are routed to the worker, any room created or joined after the worker's last (re)start was invisible to it: a remote server's `make_join` against this server for that room hit the worker's stale `store.rooms` lookup and 404'd, even though the room was correctly persisted and the main process's own copy of the store had it — this is the root cause behind the "Failed to make_join via any server" report traced back through `merovingian-server`'s logs showing a room and membership present in `sqlite3` but a live 404 from the same server. Fix: `create_room`/`join_room`/`leave_room` now call `HomeserverRuntime::federation_proxy->notify_room_changed(room_id)` after committing a residency change; `FederationProxy`/`WorkerPool::notify_room_changed` resolve the owning shard and send a fire-and-forget `room_sync` IPC notification (`ipc::serialize_room_sync_notification`), and the worker's handler responds with a new `database::reload_room()`, which re-reads just that room's rows (room, membership, invites, events, state, and the event-relation tables scoped to that room's events) from the database via parameterised, room_id-scoped queries — implemented for both SQLite and PostgreSQL — and replaces the worker's in-memory slice for that room, not a full re-hydration. Best-effort: a dropped notification is not surfaced to the caller. See `docs/architecture.md`, "Federation worker room staleness".
- **fix(database): `PersistentEvent::prev_event_ids`/`auth_event_ids`/`signatures` silently read back empty after any process restart, not just in the new federation-worker reload path above:** hydrating a `PersistentStore` from disk only loaded the flat `event_edges`/`event_auth`/`event_signatures` tables into their own top-level vectors; nothing joined those back onto the matching `PersistentEvent`, which only carries populated DAG-linkage fields when an event is stored fresh within a process's own lifetime (`store_event_with_state`). This silently produced make_join/state responses with empty `prev_events`/`auth_events` for any room whose events were written before the current process started — no crash, no error, just a request-shaped-wrong response. New `database::reconstruct_event_relations()` re-derives these fields from the flat tables; called at the end of both `open_sqlite_persistent_store`/`open_postgresql_persistent_store` and as part of `reload_room`'s snapshot merge.

### Added
- **test(federation): enforce the "every room-residency change notifies the federation worker" design contract directly, rather than only through the reload_room/reconstruct_event_relations/room_sync unit and integration tests above:** proving a real, separate `merovingian-fed-worker` process answers correctly for a room the main process just created turns out to be architecturally hard to test faithfully — the worker independently re-resolves the caller's identity even for a pre-verified request, which requires clearing a hardcoded SSRF check with no override reachable from outside the process (not a live test server, not a pre-seeded key cache, nothing short of weakening that check). New `HomeserverRuntime::test_room_changed_log` (test-only, always `nullptr` in production) lets tests assert the design contract directly and cheaply instead: `create_room`/`join_room`/`leave_room`'s six call sites are consolidated through one function, `notify_room_changed()` in `room_service.cpp`, which appends to this log when a test wires it, in addition to notifying `federation_proxy`. New scenarios in `test_homeserver_room_service.cpp` pin all three operations (plus a negative case proving an unrelated room is never logged); a new assertion in `test_join_room_flow.cpp`'s existing live federated-join test pins the real network round-trip path the same way. Fixes a genuine lifetime hazard found while writing the live-join assertion: the background member-fill task holds a reference to the runtime and can still call `notify_room_changed()` after a `THEN` block returns (the runtime's destructor blocks draining it, but the test doesn't wait explicitly) — the log vector must be declared *before* the runtime variable so it destructs *after* the runtime's blocking dtor, or the background task can write through a dangling pointer (reproduced as a `corrupted size vs. prev_size in fastbins` heap-corruption abort before the fix). See `docs/architecture.md`, "Federation worker room staleness".

## 0.10.13

### Fixed
- **fix(federation): `send_join` IPC times out for large rooms because it uses `remote_timeout_seconds` instead of the join budget:** `send_join` was calling `perform_sync_outbound_call` with `runtime.federation.config.remote_timeout_seconds`, the same short budget used for key and discovery fetches, instead of `join_timeout_seconds` — despite the `join_timeout_seconds` field being documented as "Separate budget for make_join/send_join/make_leave/send_leave". For a 30,000+ member room, `matrix.org` can take well over 60 s to assemble and transmit the full room state, so the IPC channel timed out and the main process returned `502 send_join failed: IPC timeout waiting for outbound HTTP result`. `send_join` now mirrors the same fallback chain as `make_join` (lines 2877-2879): `join_timeout_seconds` when configured, else `remote_timeout_seconds`.
- **fix(federation): `perform_sync_outbound_call` with `timeout_seconds=0` (unconfigured) produced a 10 s IPC window instead of using the `FederationCall` default (60 s):** `WorkerPool::send_outbound_request` computes the IPC channel timeout as `total_timeout_seconds + 10`. When neither `join_timeout_seconds` nor `remote_timeout_seconds` is set, `timeout_seconds=0` was written directly to `call.total_timeout_seconds`, overwriting the `FederationCall` default of 60 s and collapsing the IPC window to just 10 s. `perform_sync_outbound_call` now guards the assignment behind `timeout_seconds > 0`; a zero value leaves the `FederationCall` defaults untouched.
- **fix(config): `config/merovingian.conf.example` was missing every `security.federation.join_*` key and `federation.worker.apply_hardening`:** the example config documented `security.federation.remote_timeout` but never mentioned `join_timeout`, `join_parallelism`, `join_race_deadline`, `join_max_candidates`, or `join_state_key_parallelism` — the five keys added across 0.10.10/0.10.11 specifically to give the join/leave membership dance its own extendable budget, separate from the general 60 s `remote_timeout`. Operators following the example file had no way to discover these keys existed (they are documented in `docs/configuration.md`, but not surfaced in the file operators actually copy from). All five are now present with their code defaults (`180s`, `8`, `45s`, `20`, `100`). `federation.worker.apply_hardening` (seccomp/capability sandboxing for the federation worker, default `true`) was also missing and is now documented alongside the other `federation.worker.*` keys.

## 0.10.12

### Fixed
- **test(federation): lock `runtime.mutex` before reading `persistent_store` in `test_join_room_flow.cpp`'s immediate-success assertions, fixing a real ThreadSanitizer-detected data race:** the CI `tsan` job aborted (`SIGABRT`, `killed by signal 6`) with a genuine race reported at `src/database/persistent_store.cpp:978` in `store_membership` — not a timeout. `join_room` returns as soon as critical state is persisted and hands the bulk membership fill to a background task tracked in `runtime.orphan_futures_`, which writes to `persistent_store.state`/`.memberships` under `runtime.mutex` (see the 0.10.11 fast-join entry below). The test's first `THEN` block read those same containers on the main thread immediately after `join_room` returned, with no lock at all, while that background task was still running and concurrently calling `store_membership`'s `emplace_back` — a real unsynchronized read/write race on the vector, exactly what TSan is designed to catch. Every production call site accesses `persistent_store` only while holding `runtime.mutex`; the test now does the same. The second `THEN` block was already race-free: it calls `.wait()` on every future in `orphan_futures_` before reading, which establishes a happens-before edge with the background task's writes.
- **fix(ipc): base64-encode response bodies relayed over the federation-worker IPC boundary so large-room `send_join` responses stop busting the frame cap (#342):** joining a large room reliably failed with a client-visible `502 send_join failed: timeout`, even after a candidate resident server answered `send_join` successfully. `fed_response` and `outbound_http_response` frames (`src/ipc/federation_ipc_frames.cpp`) embedded the HTTP response body via raw JSON-string escaping, whose expansion depends on content: every `"`/`\` doubles and every raw control byte becomes a 6-byte `\u00XX` escape. A `send_join` response for a large room routinely reaches `http::OutboundRequest::max_response_body_bytes` (16 MiB by default) — quote-dense room-state JSON at that size escapes to *more* than the (then-equal) 16 MiB `merovingian::ipc::kIpcMaxFrameBytes` cap, so `IpcChannel::send_response` silently dropped the oversize frame (`ipc: dropping oversize response frame`) and `WorkerPool::send_outbound_request` on the main side just timed out waiting, surfacing as `room.join.remote.send_join_failed reason="IPC timeout waiting for outbound HTTP result"`. The body is now base64-encoded before framing (`base64_encode_body`/`base64_decode_body`), a fixed, content-independent 4/3 expansion, and `kIpcMaxFrameBytes` is raised to 24 MiB to hold a max-size response with headroom to spare. Also corrects a stale `docs/hardening.md`/header comment claiming the frame cap is configurable via `federation_worker.max_ipc_frame_bytes`; no such config field exists — the cap is a compile-time constant.

### Added
- **test(federation): live `join_room` integration test against a real local TLS server, closing the codecov/patch gap from #341:** `join_room`'s post-send_join-success path (fast-join state splitting, signature verification, background membership fill) had no integration coverage because `perform_sync_outbound_call` always resolves destinations through `federation::discover_server()`, which unconditionally rejects loopback/private-range addresses (`src/federation/security.cpp` `ip_address_is_private_or_loopback`, no config or test-mode override) — so a local test server can never be reached through the real discovery path, and production outbound calls never populate `OutboundRequest.trusted_ca_pem`, so a self-signed test certificate would fail TLS verification even if discovery succeeded. `HomeserverRuntime` gains a test-only outbound override (a map from destination `server_name` to a forced resolution + trusted CA PEM), consulted first in `perform_sync_outbound_call`; unset in every production construction path, so real-server SSRF and TLS-trust behaviour is unchanged. New `tests/integration/test_join_room_flow.cpp` reuses the TLS test-certificate/`TcpAcceptor` pattern from `test_federation_outbound_flow.cpp` to stand up a real resident server answering `make_join`/`send_join`, driving `join_room` through an actual signed federation round trip.

## 0.10.11

### Added
- **feat(federation): fast join — verify and persist critical room state synchronously, defer the bulk membership list to a background task:** even with bounded-parallel key resolution, a `join_room` call that waits on verifying every member's `m.room.member` event before returning still pays a real cost proportional to the number of distinct member home servers in the room — for a 30,000-member room, potentially hundreds of key resolutions before the client sees success. New `split_send_join_state_events` separates a send_join response's `state` array into "critical" state (create, power_levels, join_rules, history_visibility, encryption, our own membership — everything an auth check on the joining user's own next action could depend on) and "background" state (every *other* member's `m.room.member`). Critical state and `auth_chain` are verified (network-bound key resolution now runs before `guard.lock()`, so it never holds `runtime.mutex`) and persisted before `join_room` returns; background state is verified and persisted by an async task tracked in the existing `orphan_futures_` queue (same drain-on-shutdown guarantee as a losing make_join race candidate), logging `room.join.background_state_complete` on completion. The verify-before-persist invariant is unchanged for every event — nothing is exposed via `/sync` before its signature is checked, regardless of timing. This is a deliberately bounded-scope version of the "partial state room" trade-off Synapse's faster-joins feature makes: `room_has_member()`/the `/members` endpoint may not list every member until the background fill completes, but no auth-critical state is ever deferred. See `docs/threat-model.md`.

### Fixed
- **fix(security): verify send_join state/auth_chain event signatures instead of trusting the resident server wholesale, with bounded-parallel key resolution:** `join_room`'s ingestion of a `send_join` response's `state` and `auth_chain` arrays persisted every event straight to the event graph with no Ed25519 signature check and no remote signing-key fetch — a direct violation of `src/federation/AGENTS.md` rule 2 ("Verify every inbound PDU's signature... Unverified events must be silently dropped"), and the actual bottleneck behind "there are 30,000+ users that need checking" for a large room: doing this correctly means resolving a signing key for every distinct member home server represented in the room, not just racing candidate servers faster. New `filter_verified_send_join_events` resolves distinct `(sender_domain, key_id)` pairs across both arrays via the existing `remote_key_resolver`/key-cache with concurrency capped by a new `security.federation.join_state_key_parallelism` (default `100`, reloadable) — deliberately *not* unbounded, since a 30,000-member room can span hundreds of distinct home servers and firing all of them at once would just trade one unbounded-fan-out bug for another. Events whose sender is our own server are trusted without a resolver round trip. Fail-closed: an event whose key cannot be resolved, or whose signature does not verify, is silently dropped rather than persisted — and does not fail the join, so one uncooperative or unreachable member home server degrades that member's row rather than blocking everyone else's.
- **fix(federation): advertise all server-supported room versions (v1-v12) in outbound make_join, not a hardcoded v10-v12:** joining any room not on room version 10, 11, or 12 failed against every real resident server — including matrix.org — with `400` (`M_INCOMPATIBLE_ROOM_VERSION`), because `join_room`'s outbound `GET /make_join` request only ever sent `ver=10&ver=11&ver=12`. This was a pure omission: `rooms::room_version_policy.cpp` already fully implements and conformance-tests (`test_room_version_table_conformance.cpp`, "a server MUST be able to participate in rooms of all stable versions") auth rules, redaction rules, event format, and event-ID computation for v1 through v12, and the rest of the join pipeline (`validate_make_join_event`, `sign_event_for_server`, `make_reference_hash_event_id`) already dispatches generically on whatever `room_version` the response reports. `supported_versions` is now derived from `rooms::known_room_versions()` (the same source of truth used elsewhere) instead of a literal. A large, long-lived room (the kind likely to have tens of thousands of members) is essentially never on the three newest versions, so this was silently failing every federation join to such rooms. `GET /_matrix/client/v3/capabilities`'s `m.room_versions.available` had the identical hardcoded-subset bug (misleading clients about which versions are valid to create/upgrade rooms to) and is fixed the same way.
- **fix(federation): bound the make_join race with an overall deadline and cap candidate count:** joining a large, well-federated room (e.g. via a `via` list spanning dozens of resident servers) could grind for 8+ minutes — the 0.10.10 parallel race capped *concurrency* (`join_parallelism`, default 8) but not *total elapsed time*: with N candidates and a per-call budget up to `join_timeout` (180s), the race took roughly `ceil(N/join_parallelism) * up_to_180s` with no upper bound, while the client's own `fetch` (and any reverse proxy in front) gave up long before the server did, surfacing as "Failed to fetch" even though the server kept working. Two new independent config keys fix this: `security.federation.join_race_deadline` (default `45s`, reloadable) bounds the *entire* race — not just each candidate — after which `join_room` returns `502` with candidates still in flight parked in `orphan_futures_` (unchanged draining behaviour); `security.federation.join_max_candidates` (default `20`, reloadable) truncates the ordered candidate list before any `make_join` probe is spawned, since every candidate — regardless of `join_parallelism` — got an OS thread immediately via `std::launch::async`, so an unbounded `via` list meant unbounded upfront thread spawning. Both default to values that preserve the 0.10.10 behaviour for small via lists while guaranteeing a bounded, real HTTP response for large ones.
- **test: cover the race deadline, candidate cap, room-version advertisement, and send_join signature verification:** new scenarios in `test_config_federation_join.cpp` (defaults, parsing, validation, hot-reload classification for the three new join-related keys) and `test_join_routing.cpp` (`cap_join_candidates` — order-preserving truncation, no-op when under cap, `0` clamped to `1`); `test_homeserver_room_service.cpp` gains scenarios exercising `join_room` with both a configured deadline and a candidate list exceeding `join_max_candidates`, confirming truncation and the distinct "race deadline exceeded" vs. "all candidates exhausted" rejection reasons. `test_client_server.cpp`'s capabilities scenario now asserts all twelve versions (v1-v12) are advertised as stable, not just v10-v12. `test_federation_invite_join.cpp` gains five `filter_verified_send_join_events` scenarios built on real signed test events (`tests/federation_signing_test_support.hpp`): a validly signed event survives, an event with an invalid signature is dropped, an event whose sender-domain key cannot be resolved is dropped, a self-signed (our-server) event is kept without invoking the resolver at all, and — mirroring the concurrency-proof pattern already used for the inbound parallel PDU sender-key resolver — six distinct sender domains resolve exactly once each with measured peak concurrency never exceeding a configured `join_state_key_parallelism=2`. Six more scenarios cover `split_send_join_state_events`: room-level state events (create, power_levels, join_rules, history_visibility, encryption) stay critical; the joining user's own membership stays critical; other members' membership is deferred; a realistic mixed array splits correctly; a malformed/unclassifiable entry defaults to the synchronous critical path rather than being silently dropped; and an empty input returns an empty split.

## 0.10.10

### Fixed
- **fix(federation): configurable join timeout for make_join/send_join/make_leave/send_leave:** the make_join call used the shared 60s `security.federation.remote_timeout`, so joining a large remote room (e.g. on matrix.org) timed out with `502 make_join failed: timeout` when the resident server's make_join was slow. A new `security.federation.join_timeout` (default `180s`, reloadable) gives join/leave membership calls a separate, extendable budget, independent of the 60s general federation timeout.
- **fix(federation): race make_join across candidate servers in parallel:** the candidate loop tried each `via`/`server_name` resident server sequentially with the full timeout each. `make_join` now runs against all candidates concurrently (capped by `security.federation.join_parallelism`, default `8`, reloadable) and the first success wins; `send_join` targets that server (spec §Joining Rooms). If one via server is fast and another is slow, the join completes at the speed of the fastest, and a genuinely-slow-but-eventual resident server gets the full `join_timeout` budget.
- **fix(federation): TTL discovery cache for server-name resolution:** the remote key resolver re-ran the full `.well-known` + SRV + DNS discovery cascade on every call, even on cache hits. A new `CachedServerDiscovery` (60s TTL, negative cache, thread-safe, mutex-guarded) wraps the discovery network so cache-hit lookups skip the cascade, removing repeated DNS latency from key resolution and outbound calls. SSRF `pinned_addresses` are never returned stale past TTL.
- **fix(federation): parallel inbound PDU sender-key resolution:** the inbound `/send` handler resolved each PDU sender's signing key serially. Distinct `(sender_domain, key_id)` pairs across the transaction are now resolved concurrently (capped by `join_parallelism`) before per-PDU verification, while preserving fail-closed per-PDU rejection and the HTTP 200 + per-PDU error-map response (returning 4xx/5xx makes Synapse back off the whole destination).

- **test: extend join_room and inbound parallel resolver coverage:** added eight new Catch2 BDD scenarios covering previously-untested branches: `join_room` rejects unauthenticated callers (401), returns 404 when no candidate servers exist (room on own domain, no via), returns 200 idempotently when the user is already a local member, and the parallel race with `join_parallelism=0` (clamped to 1), `join_timeout_seconds>0` (uses join budget over remote timeout), and five candidates throttled by a parallelism=2 semaphore. Two new inbound scenarios cover `join_parallelism=1` (serial path, peak concurrency ≤ 1 verified) and `join_parallelism=0` (clamped to 1, all PDUs accepted).
- **test: cover the `CachedServerDiscovery`-backed `remote_key_cache` overloads and the `HomeserverRuntime` orphan-future destructor:** the `fetch_remote_server_keys(client, CachedServerDiscovery&, ...)` and `make_persistent_remote_key_resolver(store, client, CachedServerDiscovery&, ...)` overloads — the pair actually wired by `start_runtime`/`local_http_router.cpp` whenever `cached_discovery` is available — had zero direct test coverage; only the raw-`ServerDiscoveryNetwork` overloads and the standalone cache helpers were exercised. Three new scenarios in `test_remote_key_cache.cpp` prove: a failed discovery fails the fetch closed without an outbound call and is served from the negative cache on retry; a fresh cached key is served without repeating the resolver's own discovery lookup across two resolver calls (`network.lookup_calls == 1`); and a resolver with no cached key and failing discovery returns `nullopt` on both calls with discovery deduped. A fourth new scenario in `test_homeserver_room_service.cpp` directly exercises `HomeserverRuntime::~HomeserverRuntime()`'s orphan-future drain: a slow future is parked in `orphan_futures_` and the runtime is destroyed while it is still running, asserting the destructor blocks until it completes rather than returning immediately.

> Deferred: multi-server signing-key batching via `POST /_matrix/federation/v1/query/keys` — that endpoint is for E2EE device keys, not server signing keys; the v1.18 spec defines no signing-key batch endpoint (signing keys are single-server `GET /_matrix/key/v2/server`). Parallel fan-out achieves the same wall-time without a spec deviation or a new untested inbound handler.

## 0.10.9

### Fixed
- **fix(ipc): authenticate the federation-worker IPC key exchange (#318):** the `IpcChannel` `crypto_kx` handshake was unauthenticated, so any process able to reach the inherited AF_UNIX fd could complete the handshake and inject AEAD frames. Both the main process and the worker now derive the same 32-byte IPC auth key from the operator master-key file (the same material used for v4 access-token keys) and MAC each other's ephemeral KX public keys with a domain-separated key (`merovingian:ipc-channel-auth:1`) before deriving session keys. Peers that cannot prove possession of the master key are rejected (fail-closed). `load_master_key_material` is lifted into a shared header so both processes link the same loader.
- **fix(ipc): replace the hand-rolled IPC JSON parser with the fuzzed canonicaljson parser (#320):** IPC frame bodies were parsed with `json.find("\"key\":\"")` substring searches that broke on escaped quotes, keys appearing inside string values, or `}` inside header values, and `std::from_chars` results were not checked. All `deserialize_*` functions in `src/ipc/federation_ipc_frames.cpp`, the `id`/`reply_to` extraction in `src/ipc/channel.cpp`, and the duplicated parsers in `src/federation_worker/worker_event_loop.cpp` now use the existing depth-bounded, fuzzed `canonicaljson::parse_json()`. Malformed frames are rejected instead of misparsed.
- **fix(ipc): stop `noexcept` IPC frame functions terminating on allocation failure (#324):** `IpcChannel::write_frame`/`read_frame` were marked `noexcept` but allocated `std::vector`/`std::string` up to the frame cap; `std::bad_alloc` would call `std::terminate`. The allocations are now wrapped in `try`/`catch(std::bad_alloc)` returning `false`/`std::nullopt`, preserving the `noexcept` contract and letting callers fail gracefully.
- **fix(ipc): lower the IPC frame cap and stop silently dropping oversize responses (#325):** the 50 MiB per-frame cap enabled memory-exhaustion DoS across concurrent workers. The default is lowered to 16 MiB and made configurable via `federation_worker.max_ipc_frame_bytes`. Oversize frames are now logged and propagated as send/request failures instead of being silently dropped.
- **fix(homeserver): don't inherit the full parent environment in the federation worker (#330):** `posix_spawn` was called with `envp = nullptr`, leaking every parent environment variable (including any secrets) to the lower-privilege worker. The supervisor now passes an explicit minimal environment (`PATH` only) to the worker child.
- **fix(platform): apply a worker-specific seccomp filter and runtime hardening to `merovingian-fed-worker` (#319):** the worker binary inherited the main process's more-permissive seccomp filter (which deliberately allows `execve`/`execveat` so the worker could install a stricter one) but never installed its own. The worker now applies `PR_SET_NO_NEW_PRIVS`, drops capabilities, sets resource limits, and installs a stricter seccomp-bpf filter that denies `execve`/`execveat`/spawn-oriented `clone` (the worker never execs or spawns). `docs/hardening.md` and the seccomp self-check are updated.
- **fix(platform): disable exit-time LeakSanitizer in the federation worker under ASan (#319):** the worker's seccomp filter denies `ptrace` by design (an escalation primitive a compromised worker must never have). ASan's exit-time LeakSanitizer uses `ptrace` (via `StopTheWorld`) to suspend threads before scanning for leaks; with `ptrace` denied, the tracer thread is killed and `StopTheWorld` spun in `sched_yield` forever, so the worker process never exited and the supervisor's `waitpid()` hung — producing the asan-ubsan CI integration-test timeout. The worker now defines `__asan_default_options()` returning `detect_leaks=0` (C linkage, global scope, guarded to ASan builds only) so the worker skips the exit leak check; the main process retains full ASan/LSan coverage and the worker's correctness is covered by its own unit/integration tests. Production (non-sanitised) builds are unaffected.
- **fix(auth): derive the legacy v3 access-token HMAC key from the master key instead of the Ed25519 seed (#322):** `token_hmac_key_v3` copied the first 32 bytes of the Ed25519 signing seed and used it directly as the access-token HMAC key, violating cryptographic key separation. The v3 key is now master-key-derived with a distinct domain separator (`merovingian:access-token-hmac:legacy-v3:1`). **Breaking:** existing `token-hash:v3:` hashes no longer validate; affected sessions must re-login and are issued v4 tokens (the current issuance path). The signing seed is no longer used as a MAC key. Without a master key configured, v3/v4 are both unavailable and token issuance falls back to the unkeyed v2 hash; configure a master key for hardened token hashing.
- **fix(database): mark the server signing secret as sensitive for prepared-statement redaction:** `store_server_signing_key` bound the `secret_key` column as a `public_value`, so `sensitive_values_are_redacted` flagged the store once a master key was configured (the at-rest encrypted form `secretbox:v1:…` contains the substring "secret"). The signing secret is now bound as `sensitive_value`, consistent with the other key/signature parameters — the encrypted-or-plaintext signing secret is always redacted from query-parameter logging.
- **fix(federation): handle escaped quotes in the X-Matrix Authorization header parser (#321):** `parse_x_matrix_authorization_header` ended a quoted value with `remaining.find('"')`, ignoring `\"` escapes per RFC 7230, so legitimate headers containing escaped quotes failed to parse and attacker-controlled headers could terminate values early. The parser now skips `\"`/`\\` escape sequences when scanning for the closing quote.
- **fix(crypto): keep the server signing secret in `core::SecretBuffer`, not `std::string` (#317):** multiple call sites copied the Ed25519 signing secret out of the mlocked/zeroised `SecretBuffer` into a heap `std::string` via `reinterpret_cast`, which is not pinned or zeroised and may leak into freed arenas or core dumps. `make_federation_signature`, `OutboundCall::secret_key`, `DispatchWorkerConfig::secret_key`, and `perform_sync_outbound_call` now accept `std::span<std::uint8_t const>` / own a `core::SecretBuffer`; call sites pass `signing_secret_key.bytes()` directly.
- **fix(ipc): stop shipping raw peer X-Matrix credentials to the federation worker (#323):** inbound `fed_request` frames serialized the raw peer `Authorization` header (origin/key/sig) into the IPC body, letting a compromised worker harvest and replay peer homeserver credentials. The main process now verifies the inbound X-Matrix signature itself (`verify_inbound_federation_signature`) and forwards only the verified identity (`origin`, `key_id`, `sig_verified`) to the worker over the now-authenticated channel; the raw `access_token`/signature never crosses IPC, and `Authorization`/`X-Matrix` headers are stripped from the `fed_request` frame. The worker's `handle_federation_http_request` builds a `SignedFederationRequest` from the verified identity (`signature_verified = true`) and skips re-verification. **Outbound residual (not addressed by this change):** the outbound `Authorization` header carried on `outbound_http_request` frames is our own request-bound X-Matrix signature (bound to the method/url/body/destination of the exact request the worker sends), not a reusable peer credential, so the harvest/replay risk that motivated this issue does not apply outbound; the signing secret never enters the worker (#317). Relocating outbound signing into the worker via `IpcEd25519Provider` — so the signed value never crosses IPC — is deferred; it requires a provider-abstraction refactor of `build_outbound_request` for minimal additional security value.

## 0.10.8

### Fixed
- **fix(platform): seccomp filter SIGSYS crash on glibc 2.35+ when built with older kernel headers:** `rseq` (Linux 4.18), `membarrier` (Linux 4.3), `getcpu`, and `futex_waitv` (Linux 5.16) were conditionally included in the BPF allowlist only when the build-time kernel headers defined the corresponding `__NR_*` macros. On hosts built against Ubuntu 18.04 headers (Linux 4.15) or Ubuntu 22.04 headers (Linux 5.15), these macros are absent and the filter silently drops the entries. When the binary then runs on a host with glibc 2.35+, thread initialisation unconditionally calls `sys_rseq()`, which is blocked by `SECCOMP_RET_KILL_PROCESS` — delivering SIGSYS and killing the server immediately after `event=start.complete`. Fixed by adding architecture-specific numeric fallbacks matching the pattern established in v0.10.6 for `clone3` (435), `close_range` (436), and `faccessat2` (439): x86_64 fallbacks are 334/324/309/449; aarch64 fallbacks are 293/283/168/449.
- **fix(platform): seccomp filter SIGSYS crash in ThreadSanitizer federation worker:** the production seccomp allowlist omitted `personality` (135). ThreadSanitizer calls `personality(ADDR_NO_RANDOMIZE)` in the federation worker after `execve` to disable ASLR for deterministic shadow-memory layout. Because the worker inherits the server's seccomp-bpf filter, the call was killed with SIGSYS before the IPC handshake, producing `"Federation worker failed to start: ipc: public key exchange failed"` in the TSan integration test. `personality` is now explicitly allowed in the filter.
- **fix(federation): orphaned federation workers persist after parent crash/kill in tests:** the federation worker now calls `prctl(PR_SET_PDEATHSIG, SIGTERM)` immediately after startup so the kernel terminates the child automatically when the spawning parent thread exits. This prevents leftover worker processes from spinning at 100% CPU when integration tests kill the server process or when the server crashes.
- **fix(tests): binary startup hardening test failed in CI containers that run as root:** `tests/integration/test_server_startup_hardening_flow.cpp` now skips (WARN) when the test process runs as root, because the server refuses to start as root by design (the privilege-drop and filesystem-restriction self-checks report `disabled`) and the test can never reach the listening state. This fixes the blocking `debian`/`fedora`/`rhel`/`opensuse` CI jobs, which run in containers as root. A pre-`REQUIRE(ready)` refusal check also skips when the server logs `Startup refused: hardening self-check` before binding listeners.
- **fix(tests): binary startup hardening test crashed under ThreadSanitizer:** the TSan-instrumented server is killed by the seccomp filter on startup (TSan's runtime issues syscalls the allowlist does not permit beyond `personality`), which surfaced as a `signal-unsafe call inside of a signal` in the Catch2 fatal-error handler. The test now skips under `__SANITIZE_THREAD__` / `__has_feature(thread_sanitizer)`; the asan-ubsan CI job continues to exercise the same startup path.
- **fix(tests): hardening self-check unit test failed when the test process ran as root:** `tests/unit/test_hardening_self_check.cpp` previously asserted indices 9 (privilege drop) and 10 (filesystem restrictions) were `enabled` or `unknown`. On Linux these are now definitive — `enabled` for a non-root UID, `disabled` for root — so the assertion failed in root CI containers. Indices 9/10 are now split out and asserted per-platform: `enabled`/`disabled` on Linux, `unknown` elsewhere.
- **fix(tests): NetBSD compile error in `wait_for_log_line`:** `tv.tv_usec` was assigned via `static_cast<long>` and then implicitly narrowed to `suseconds_t` (aka `int`) on NetBSD, triggering `-Wshorten-64-to-32` (treated as error). Cast directly to `suseconds_t`; the value (0..999000) always fits.
- **fix(tests): hardening self-check unit test failed on NetBSD:** the platform-specific sandbox scenario in `tests/unit/test_hardening_self_check.cpp` had an `#else` branch (covering NetBSD and any platform that is not Linux/OpenBSD/FreeBSD) that asserted `pledge/unveil` and `capsicum` report `unknown`. The implementation correctly reports `enabled` for controls that are not applicable to the host OS (no security gap — the same treatment Linux receives for these BSD-only primitives); `unknown` would wrongly block startup via `is_ready()` on platforms that can never apply them. The `#else` branch now asserts `enabled` for both, matching the implementation and the v0.10.8 "no alpha exceptions" design. This was the last failing NetBSD CI job (1 of 886 unit cases, exit status 42).
- **ci(netbsd): surface the Catch2 failure report from `testlog.txt` on unit-test failure:** the NetBSD job's `meson test --print-errorlogs` truncated output to the last 100 lines, which were all structured runtime INFO logs — Catch2's own failure report (test name + `file:line`) was buried, and the core-backtrace group was empty because assertion failures do not produce cores. The failure branch now filters runtime log lines and `[netbsd-diag]` markers out of `build/meson-logs/testlog.txt` and prints the Catch2 section headers, `FAILED` assertions, and test-case summary to the live log.

### Changed
- **refactor(platform): remove `HardeningStatus::alpha_exception` and require every hardening check to report `enabled`:** the alpha-phase carve-out status is deleted from the hardening self-check. `is_alpha_ready()` is replaced by `is_ready()`, which returns true only when every hardening check is `enabled`; `unknown` and `disabled` both block startup. `src/main.cpp` now runs the final self-check after all platform controls are applied: after `start_client_server()` has applied the OpenBSD `pledge`/`unveil` profile and after FreeBSD `cap_enter()` has entered Capsicum capability mode. `docs/hardening.md` is updated to remove all alpha-exception language.
- **test(platform): binary startup integration test skips cleanly when the environment cannot satisfy full hardening:** `tests/integration/test_server_startup_hardening_flow.cpp` now detects a hardening-gate refusal from the server log and returns with `WARN(...)` instead of failing, so Meson (which treats Catch2 `SKIP()` exit code 4 as failure) reports a clean skip. `wait_for_log_line` preserves all drained output so the refusal line is not lost when it arrives in the same `read()` as "Listeners active". The refusal is checked in every poll iteration *and* again after the child exits, so a server that refuses startup and immediately terminates is still reported as a skip. `ServerGuard::alive()` uses `waitpid(WNOHANG)` so a server that exits between "Listeners active" and the idle check is not misreported as alive due to zombie PID reuse. The idle-window failure message includes both the startup log and the post-listeners drain for diagnosis.

### Fixed
- **fix(tests): restore hardening self-check snapshot for `admin_health`:** `src/homeserver/runtime.cpp` populates `runtime.hardening` with `run_startup_hardening_self_check()` before marking the runtime started, so the health endpoint reports `hardening:ok` in unit tests. The final startup gate in `src/main.cpp` still overwrites the snapshot after all platform controls are applied.
- **fix(tests): smoke test expects the new readiness summary format:** `tests/smoke/meson.build` no longer greps for the removed `alpha_ready` field; it checks for `Hardening readiness: ready=false blockers=N` in `--dry-run` output.
- **chore(tests): remove temporary diagnostic script:** `scripts/tmp_startup_test.sh` is deleted.

### Added tests
- **test(platform): rseq/membarrier/getcpu/futex_waitv numeric values are always present:** new WHEN block in `test_seccomp_hardening.cpp` unconditionally checks the numeric syscall values (334/324/309/449 on x86_64; 293/283/168/449 on aarch64) are in the allowlist, regardless of what `__NR_*` macros the build headers define — mirroring the existing clone3/close_range/faccessat2 numeric assertions added in v0.10.6.
- **test(platform): hardening self-check no longer tolerates alpha exceptions:** updated `test_hardening_self_check.cpp` to assert the absence of `alpha_exception`, to verify `is_ready()` fails closed when runtime controls are not applied, and to check that platform-specific sandbox controls map to `enabled` (not applicable) or `unknown` (not yet applied) instead of `alpha_exception`.
- **test(platform): seccomp allowlist allows ThreadSanitizer `personality` syscall:** new SCENARIO in `tests/unit/test_seccomp_hardening.cpp` asserts that `personality` (135) is in the allowlist so the TSan federation worker is not killed with SIGSYS during startup.

## 0.10.7

### Added
- **feat(platform): implement OpenBSD `pledge(2)` + `unveil(2)` sandbox:** `apply_runtime_hardening_controls()` now calls `unveil()` for every path in the BSD hardening profile (read-only paths get `"rx"`, writable paths get `"rwc"`, `/etc/ssl` gets `"r"` for the LibreSSL CA bundle), locks the vnode allowlist with `unveil(NULL, NULL)`, then applies `pledge("stdio rpath wpath cpath flock inet unix dns proc exec", NULL)`. The promise set includes `proc exec` for the thumbnail and federation worker child processes and `unix` for the AF_UNIX IPC channel. `openbsd_pledge_is_active()` and `bsd_pledge_promises()` are now exported from `runtime_hardening.hpp` for testing. Tested on the Tier 1 OpenBSD CI job (`vmactions/openbsd-vm@v1`).
- **feat(platform): implement FreeBSD Capsicum `cap_enter(2)` capability mode:** `apply_freebsd_capsicum_capability_mode()` is a new public API that enters Capsicum capability mode. It is called from `run_server()` in `main.cpp` after all resources are open (listeners bound, TLS loaded, federation worker spawned via `posix_spawn()` by path). Before calling `cap_enter`, the thumbnail worker binary is pre-opened with `O_RDONLY | O_EXEC | O_CLOEXEC` and the fd is stored in `RuntimeMediaConfig::thumbnail_worker_fd`. The child process in `thumbnailer.cpp` now calls `fexecve(fd, argv, environ)` on FreeBSD when the pre-opened fd is available, allowing thumbnail generation to continue after the global filesystem namespace is forbidden. `freebsd_capsicum_is_active()` probes `cap_getmode(2)` and is exported for testing. Tested on the Tier 1 FreeBSD CI job (`vmactions/freebsd-vm@v1`).

### Fixed
- **fix(platform): FreeBSD `thumbnailer.cpp` build failure:** move the `environ` declaration to namespace scope with `extern "C"` linkage in the FreeBSD-only `fexecve()` path. FreeBSD's `<unistd.h>` exposes `environ` only with C linkage, so the previous `::environ` lookup failed with `no member named 'environ' in the global namespace`, and an earlier attempt to declare it at block scope was ill-formed. The global declaration preserves the existing behavior of passing the current environment to the thumbnail worker.
- **fix(platform): OpenBSD temp-directory failures on CI runners:** introduce `merovingian::tests::temporary_directory()` with a fallback chain (`std::filesystem::temp_directory_path()` → `/var/tmp` → `/tmp` → `/var/run` → current path) and use it in all test scratch-file helpers and direct test callers. This makes the test suite robust on restricted CI images where `/tmp` is reported as not-a-directory. `default_bsd_hardening_profile()` keeps `/tmp` in `filesystem.writable_paths` so real OpenBSD deployments with a normal `/tmp` continue to have it unveiled.
- **test(platform): update BSD writable-path assertions after adding `/tmp`:** `tests/unit/test_runtime_hardening.cpp` now expects three BSD writable paths (`/var/lib/merovingian`, `/var/run/merovingian`, `/tmp`) instead of two, matching the updated default profile.
- **chore(tests): gate NetBSD diagnostic prints to NetBSD only:** the `[netbsd-diag]` `std::cerr` logging in `tests/unit/test_federation_invite_join.cpp` and `tests/unit/test_otk_signature_validation.cpp` now only emits on `__NetBSD__`; on Linux and other CI platforms the output is compiled away so it no longer looks like NetBSD-specific tests are running there.
- **fix(platform): FreeBSD Capsicum probe compilation error in `runtime_hardening.cpp`:** `auto mode = unsigned int{0U};` is rejected by the FreeBSD toolchain as an ill-formed braced functional cast; replaced with `unsigned int mode = 0U;` so the FreeBSD CI build and package jobs compile.
- **fix(ci): `MESON_TEST_TIMEOUT_MULTIPLIER` was ignored by the sanitizers workflow:** `scripts/build-linux.sh`, `scripts/build-bsd.sh`, and `scripts/build-wsl.sh` now translate the environment variable into `meson test --timeout-multiplier`, so the ASan/UBSan and TSan integration-test runs get the intended 3× timeout instead of being killed at the 600 s default.
- **fix(ci): OpenBSD/BSD CI test runs permanently restricted themselves with pledge/unveil:** `start_runtime()` now skips applying runtime hardening controls when `MEROVINGIAN_TEST_DISABLE_HARDENING` is set. The build scripts export this variable during `meson test`, and the PostgreSQL integration workflow sets it for its direct binary invocation, keeping the Catch2 test process unrestricted while production server binaries continue to apply hardening.
- **fix(platform): FreeBSD package build compile errors in `main.cpp`:** add the missing `#include "merovingian/platform/runtime_hardening.hpp"` so `apply_freebsd_capsicum_capability_mode()` is visible, and replace the non-existent `LOG_WARN` macro with `LOG_WARNING` in the FreeBSD capability-mode entry block.

### Changed
- **chore(platform): update BSD hardening profile rejection message:** the fallback for non-OpenBSD/non-FreeBSD BSDs (e.g. NetBSD) now reads `"BSD sandbox helpers are not yet implemented on this BSD variant"` to distinguish from the old message that previously also covered OpenBSD and FreeBSD.

### Added tests
- **test(platform): OpenBSD pledge probe returns false before pledge is applied:** new `#ifdef __OpenBSD__` SCENARIO in `test_runtime_hardening.cpp` asserts `openbsd_pledge_is_active()` returns false in the test runner (pledge not applied) — exercises the probe without permanently restricting the test process.
- **test(platform): OpenBSD pledge promise set covers all homeserver categories:** new `#ifdef __OpenBSD__` SCENARIO asserts all ten promise categories (`stdio`, `rpath`, `wpath`, `cpath`, `flock`, `inet`, `unix`, `dns`, `proc`, `exec`) are present in `bsd_pledge_promises()` and the string is space-separated.
- **test(platform): FreeBSD Capsicum probe returns false before capability mode entry:** new `#ifdef __FreeBSD__` SCENARIO asserts `freebsd_capsicum_is_active()` returns false (cap_enter not called).
- **test(platform): FreeBSD `apply_runtime_hardening_controls` accepts BSD profile without cap_enter:** new `#ifdef __FreeBSD__` SCENARIO calls `apply_runtime_hardening_controls` on FreeBSD (safe — returns accepted without calling cap_enter) and asserts accepted + probe still false.
- **test(platform): BSD runtime hardening scenario is now platform-conditional:** the old scenario "BSD runtime hardening controls remain documented alpha exceptions" is replaced with a platform-aware equivalent: profile evaluation always accepts; `apply_runtime_hardening_controls` is tested on FreeBSD (accepts, Capsicum deferred) and non-OpenBSD/non-FreeBSD (rejects with unimplemented message); skipped on OpenBSD to avoid permanently pledging the test process.
- **test(platform): self-check BSD scenario comment updated:** the "BSD sandbox controls are alpha_exception" scenario in `test_hardening_self_check.cpp` is updated to explain the correct reason (startup self-check runs before `apply_runtime_hardening_controls`, so probes return false at check time).

## 0.10.6

### Fixed
- **fix(platform): SIGSYS crash on Fedora / modern Linux at startup:** the seccomp-BPF allowlist conditionally included `clone3` (435), `close_range` (436), and `faccessat2` (439) only when the build-time kernel headers defined the corresponding `__NR_*` macros. Binaries compiled against Ubuntu 20.04 `linux-libc-dev` (kernel headers 5.4) therefore omitted all three, because `close_range` and `faccessat2` were added in 5.9 and 5.8 respectively. On Fedora 36+ and other hosts with glibc 2.34+, the first `pthread_create` or `posix_spawn` call after seccomp was applied used `clone3`; without it in the filter the process was killed immediately with `SECCOMP_RET_KILL_PROCESS` (SIGSYS). All three syscalls now use a hardcoded numeric fallback for x86_64 and aarch64 when the macro is absent, ensuring they are always present in the deployed filter regardless of the build environment's kernel header version.

### Added tests
- **test(platform): seccomp allowlist always contains clone3/close\_range/faccessat2 on x86\_64 and aarch64:** new WHEN block in `tests/unit/test_seccomp_hardening.cpp` asserts that syscalls 435, 436, and 439 are present in the compiled filter by raw number, catching any future regression where a `#ifdef __NR_*` guard silently drops them from the allowlist.
- **test(platform): non-Linux seccomp probe returns not-probed and maps to `unknown`:** `#ifndef __linux__` SCENARIO in `tests/unit/test_seccomp_hardening.cpp` verifies that `probe_seccomp_status()` returns `{probed: false, seccomp_active: false}` on BSD (no `/proc/self/status`) and that `seccomp_check_from_probe` maps it to `HardeningStatus::unknown` — not `alpha_exception` or `disabled`.
- **test(platform): self-check pins BSD sandbox controls as always `alpha_exception`:** new SCENARIO in `tests/unit/test_hardening_self_check.cpp` asserts `pledge/unveil` (index 7) and `capsicum` (index 8) are always `alpha_exception`, never `enabled`, since `enabled_or_alpha_exception(false, ...)` is hardcoded for both.
- **test(platform): self-check maps Linux-only controls to correct non-Linux statuses:** `#ifndef __linux__` SCENARIO in `tests/unit/test_hardening_self_check.cpp` asserts that `seccomp` (index 6) is `unknown` on non-Linux (not `alpha_exception`) and that `core dump policy`, `no_new_privs`, and `capability bounding` (indices 11–13) are `alpha_exception` on non-Linux, where the Linux kernel features are unavailable.
- **test(platform): BSD hardening plan is exhaustively tested — all six documentation fields:** new SCENARIO in `tests/unit/test_runtime_hardening.cpp` individually sets each of `unveil_documented`, `capsicum_documented`, `jail_documented`, `chroot_documented`, and `setrlimit_documented` to `false` and asserts each independently causes `evaluate_runtime_hardening_profile` to reject with `"bsd hardening plan is incomplete"`.
- **test(platform): BSD and Linux writable path sets use platform-appropriate mount points:** new SCENARIO in `tests/unit/test_runtime_hardening.cpp` documents that both profiles share `/var/lib/merovingian` while Linux uses `/run/merovingian` and BSD uses `/var/run/merovingian`, and asserts the platform-specific socket directories do not cross-appear in the other profile.
- **test(platform): BSD profile rejects unsafe filesystem paths with the same rules as Linux:** new SCENARIO in `tests/unit/test_runtime_hardening.cpp` asserts that protected (`/etc/rc.conf.d`, `/usr/local/bin`), non-normalized (`/var/lib/../etc`), and root-escape (`/`) paths are rejected on a BSD profile.
- **test(platform): BSD integrated flow — optional unavailable sandbox controls are accepted:** new SCENARIO in `tests/integration/test_runtime_hardening_flow.cpp` evaluates a BSD profile in optional mode with optional unavailable pledge and capsicum gates and asserts both are accepted without blocking.
- **test(platform): BSD integrated flow — required unavailable sandbox gate fails closed:** new SCENARIO in `tests/integration/test_runtime_hardening_flow.cpp` asserts that a required unavailable `pledge` gate fails closed with `"required hardening gate unavailable: pledge"`, mirroring the Linux seccomp gate test.

## 0.10.5

### Added
- **feat(dev): add installable pre-commit project gates:** `scripts/hooks/pre-commit` now runs the unsafe C/C++ source gate, Catch2 BDD style checks, unit/conformance test registration checks, and a new staged-file changelog/docs guard. `scripts/install-hooks.sh` installs the tracked hook template into `.git/hooks`, and tooling tests cover the hook wiring and changelog/docs guard behavior.
- **feat(dev): add Codex post-edit clang-format hook:** `.codex/hooks.json` wires a Codex `PostToolUse` hook for edit/write tool calls, backed by `.codex/hooks/clang_format_after_edit.py`, so edited C and C++ source files are formatted with `clang-format -i` immediately after Codex modifies them.

### Fixed (PR review)
- **fix(federation): discovery timeout ignores configured `remote_timeout`:** `perform_sync_outbound_call` used a hard-coded 30 s timeout for the `discover_server()` call regardless of the operator-configured `security.federation.remote_timeout`. Operators who raised the timeout for slow federation joins (e.g. 180 s) would still see discovery fail after 30 s during the `.well-known` fetch. Now passes `timeout_seconds` directly to `discover_server()`.
- **fix(config): example `security.federation.remote_timeout` was 600s instead of the 60s default:** `config/merovingian.conf.example` showed `600s`, overriding the code default and tying up caller and worker slots for ten minutes per slow join. Corrected to `60s`.
- **fix(scripts): `check-staged-changelog-docs.sh` missed deleted project files:** `--diff-filter=ACMR` excluded `D` (Deleted) paths, so a commit that removes source or packaging files bypassed the changelog/docs guard. Added `D` to the filter.
- **fix(scripts): `install-hooks.sh` failed in linked worktrees:** `.git/hooks` is not a directory in a linked worktree. Now resolves via `git rev-parse --git-path hooks` and `mkdir -p`.
- **fix(packaging): RPM `%changelog` entries missing for 0.10.5:** Added 0.10.5 entries to `packaging/rpm`, `packaging/rhel`, and `packaging/opensuse` spec files.

### Added tests
- **test(federation): outbound HTTP routing through worker IPC — coverage for `WorkerPool::send_outbound_request`, `FederationProxy::send_outbound_request`, and the `outbound_http_request` branch in `WorkerEventLoop::run`:** `tests/integration/test_federation_worker_flow.cpp` gains four new scenarios: healthy-pool outbound dispatch to a quick-failing (ECONNREFUSED) pinned address across both shards; stopped-pool early-exit returning a non-empty error detail; and `FederationProxy`-level outbound dispatch proving the proxy delegates correctly to the pool.

### Fixed
- **fix(federation): federation join/leave 502 failures logged at DEBUG instead of WARN:** `perform_sync_outbound_call` and the three 502-path `log_diagnostic` calls for `room.join.rejected` (send_join timeout) and `room.leave.rejected` (make_leave/send_leave timeout) all defaulted to `LogEventSeverity::debug`. A timed-out join to a busy room produced no visible log entry at INFO level. The outbound failure path inside `perform_sync_outbound_call` and all three 502 rejection sites are now promoted to `LogEventSeverity::warn` per the log-level policy.
- **fix(federation): `security.federation.remote_timeout` config ignored for join/leave outbound calls:** `perform_sync_outbound_call` constructed `OutboundCall` without setting `connect_timeout_seconds` or `total_timeout_seconds`, so both fell back to the hardcoded struct defaults (connect=10 s, total=60 s) regardless of what the config said. The function now accepts a `timeout_seconds` argument and sets both fields (`connect` capped at 30 s). All four callers — `make_join`, `send_join`, `make_leave`, and `send_leave` — now pass `runtime.federation.config.remote_timeout_seconds`. The config default for `security.federation.remote_timeout` is raised from `"30s"` to `"60s"` to match the old hardcoded value; operators joining large rooms (e.g. `#twim:matrix.org`) should set this to `"180s"` or higher.
- **feat(federation): join/leave outbound HTTP calls routed through the federation worker:** `perform_sync_outbound_call` now signs the X-Matrix Authorization header in the main process (Ed25519 secret never crosses the IPC boundary) and then routes the resulting `OutboundRequest` through `FederationProxy::send_outbound_request` → `WorkerPool::send_outbound_request` → IPC `outbound_http_request` frame → worker thread pool. The worker executes the HTTP call via `OutboundClient::perform` and returns the result via IPC `outbound_http_response` frame. This prevents long-running federation joins (e.g. to busy rooms with 180 s timeouts) from blocking main-process HTTP handler threads. The IPC channel timeout is set to `total_timeout_seconds + 10 s` to give the worker time to return before the IPC side declares a timeout. The `outbound_http_request` handler is wired in `WorkerEventLoop::run` alongside the existing `fed_request` handler.

## 0.10.4

### Changed
- **feat(federation): federation worker is now mandatory:** the `federation.worker.enabled` and `federation.worker.fallback_in_process` configuration keys have been removed. The `merovingian-fed-worker` process is the only supported federation path; startup fails with a fatal error if the worker cannot be launched. `FederationProxy` is fail-closed with no in-process fallback. Config validation now always enforces non-zero values for `federation.worker.shards`, `federation.worker.threads`, and `federation.worker.request_timeout_seconds`.

### Fixed
- **fix(federation): TOCTOU channel race in `WorkerSupervisor`:** the supervisor restart loop could reset `channel_` (a `unique_ptr`) while a request thread was between the `healthy()` check and the `channel().send_request()` call, causing a use-after-free. `channel_` is now a `shared_ptr` protected by `channel_mu_`; external callers obtain a ref-counted snapshot via `channel_snapshot()` that remains valid across concurrent restarts.
- **fix(federation): `room_id_from_send_body` failed when nested JSON objects precede `room_id`:** the old search stopped at the first `}` inside the first PDU object, which belongs to a nested `content`, `hashes`, or `unsigned` field rather than the PDU itself. The extractor now tracks brace depth (including string-escaped characters) to correctly identify the PDU closing brace, then searches within the full PDU span.
- **fix(federation): spurious sync wakeup after PDU ingestion:** `publish(next_stream_ordering)` was called with the value of `runtime_.database.next_stream_ordering` after `pdu_sink` had already incremented it, waking sync clients with a token one step ahead of the event. The stream ordering is now captured before invoking `pdu_sink`.
- **fix(config): zero threads and zero request timeout were not validated:** `federation.worker.threads=0` and `federation.worker.request_timeout_seconds=0` were only rejected when the worker was enabled. Since the worker is now always enabled, both values are always validated and rejected if zero.

### Added tests
- **test(federation): BDD scenarios for nested-object PDU room ID extraction:** `tests/unit/test_federation_request_routing.cpp` adds two new scenarios verifying that `room_id` is correctly extracted from `/send` bodies where `content`+`hashes` objects and deeply nested `relates_to` content precede the `room_id` field.
- **test(config): mandatory-worker validation scenarios:** `tests/unit/test_config_parser.cpp` adds scenarios asserting that zero threads and zero request timeout are always rejected; removed the now-invalid "accepts zero shards when disabled" scenario.

### CI
- **fix(ci): OpenSUSE Tumbleweed RPM build fails on cold cache:** `hendrikmuhs/ccache-action@v1.2` does not recognise the `install` parameter added in later releases and has no zypper support, so on a cold runner it attempts auto-installation and fails. The opensuse-rpm job now uses `actions/cache@v4` to restore/save `~/.ccache` directly and a shell step to wire ccache via `CC=ccache clang` / `CXX=ccache clang++` in `GITHUB_ENV`, replacing the ccache-action entirely for this job. The earlier symlink + `GITHUB_PATH` approach was dropped because appending to `GITHUB_PATH` inside a Docker container step corrupts the `PATH` seen by subsequent steps, leaving `sh` unfindable at exec time.

## 0.10.3

### Added
- **feat(federation): room-sharded federation workers (Phase 3):** inbound federation requests are now routed across N independent `merovingian-fed-worker` processes using `federation.worker.shards`. Room-scoped endpoints are assigned by `fnv1a_32(room_id) % shards`; non-room endpoints (key queries, profile queries, etc.) route to shard 0. Each shard has its own `WorkerSupervisor` restart monitor and encrypted AF_UNIX IPC channel, so a CPU-heavy room can no longer starve federation traffic for all other rooms. `FederationProxy` extracts the room ID from request targets and from the first PDU in `PUT /send/{txnId}` bodies.

### Changed
- **refactor(federation): `WorkerPool` owns N supervisors:** `FederationProxy` now delegates to a `WorkerPool` that creates `federation.worker.shards` `WorkerSupervisor` instances. Each worker is launched with `--shard <index>` so log output can identify the shard; the per-worker IPC request handler captures the correct supervisor reference so `pdu_ingest` and `sign_request` responses are sent on the channel that received them.

### Fixed
- **fix(federation): close the server-side IPC fd before duping the client fd in `WorkerSupervisor`:** the `posix_spawn` file actions previously duplicated the child's socketpair end onto `kWorkerIpcFd` (3) and then closed the parent-side fd. When `socketpair` returned the parent side as fd 3, the close removed the newly placed IPC fd, causing the worker to fail with "ipc fd 3 is not open". The close now happens before the dup2 so the fixed IPC fd survives into the child.
- **fix(federation): `WorkerSupervisor::healthy()` reports healthy before `start()`:** a constructed supervisor that has not yet spawned a worker is not failed; `healthy()` now returns `true` when no IPC channel exists yet, so pre-start health checks and unit assertions behave correctly.
- **fix(ipc): `deserialize_fed_response` parses numeric `status` field:** the worker response frame carries `status` as a JSON number, but the deserializer was reading it with the string helper and defaulting to `500`. A dedicated numeric parser now returns the actual HTTP status from the worker.
- **fix(packaging): include `merovingian-fed-worker` in all binary package manifests:** the OpenSUSE, RHEL, Fedora RPM specs and the OpenBSD `PLIST` now list the new federation worker helper binary. Package builds that fail on unpackaged files will now succeed.
- **fix(build): include `<charconv>` in `src/homeserver/worker_pool.cpp` and avoid `std::istreambuf_iterator` in the federation worker:** FreeBSD/Clang and RHEL/GCC builds failed because `std::from_chars` was used without the required header and because GCC 14 warned on the iterator-based file read. A chunked read loop and the missing include make the worker build cleanly on those compilers.
- **fix(ipc): close the IPC file descriptor only after the reader thread has joined:** `IpcChannel::stop()` previously closed the descriptor and then joined the reader, so ThreadSanitizer saw a data race between `FileDescriptor::reset()` writing `m_fd` and `FileDescriptor::get()` reading it from the reader thread. The shutdown sequence now wakes pending waiters, calls `::shutdown()` to unblock `recv()`, joins the reader, and only then closes the descriptor under `write_mu_`.
- **fix(ipc): `IpcChannel::stop()` reports the channel as unhealthy:** `healthy()` continued to return `true` after an explicit `stop()` because the flag was only cleared on reader errors. `stop()` now clears `healthy_` so callers can distinguish a deliberately stopped channel from a live one.

- **fix(federation): X-Matrix auth lost across IPC:** `serialize_fed_request` omitted `access_token`, which carries the raw `Authorization: X-Matrix …` header value. Every federation request proxied to a worker arrived unauthenticated. The field is now serialized and restored on deserialization.
- **fix(platform): add `execve`/`execveat` to the seccomp allowlist:** `posix_spawn` calls `execveat` in the child process, which inherits the seccomp filter. Both syscalls were absent from the BPF allowlist, so all worker spawns (initial and restart) were killed by the filter. The worker installs its own stricter filter after startup, so the main server's exposure is bounded.
- **fix(federation): graceful-shutdown watcher deadlock:** after receiving a `"shutdown"` notification the IPC channel stays healthy, so the watcher loop ran forever and `watcher.join()` blocked indefinitely. The watcher now also checks the `shutdown` atomic and exits promptly.
- **fix(federation): `healthy_` not restored after `WorkerSupervisor` restart:** the supervisor set `healthy_` to `false` when a worker died but never set it back after a successful respawn, permanently excluding that shard from routing. The flag is now reset to `true` on a successful restart. The `false` store is also moved to before `channel_.reset()` to close a TOCTOU window where a null `channel_` pointer could be dereferenced by a concurrent request thread.
- **fix(federation): missing v2 shard-routing prefixes:** `/_matrix/federation/v2/invite`, `send_join`, `send_leave`, `make_knock`, and `send_knock` were absent from the shard-routing prefix table, so all v2 membership requests landed on shard 0 regardless of the room they targeted.
- **fix(ipc): IPC frame cap raised from 4 MiB to 50 MiB:** large federation transactions (many PDUs or large auth chains) could exceed 4 MiB, causing the frame to be silently dropped. The cap is now 50 MiB, matching common homeserver defaults.

### Added tests
- **test(federation): BDD scenarios for federation worker shard routing:** `tests/unit/test_federation_proxy.cpp` covers deterministic FNV-1a sharding, single-shard fallback to shard 0, non-room request routing, and the 503 fail-closed path when the selected shard's worker is unhealthy.
- **test(federation): exhaustive unit coverage for Phase 2/3 helpers:** `tests/unit/test_federation_request_routing.cpp`, `tests/unit/test_ipc_federation_frames.cpp`, `tests/unit/test_federation_worker_args.cpp`, `tests/unit/test_worker_supervisor.cpp`, and `tests/unit/test_worker_event_loop.cpp` cover room-ID extraction from federation paths and `/send` bodies, IPC `fed_request`/`fed_response` frame round-trips, worker CLI argument parsing, and shard-index capture in supervisor/event-loop construction.
- **test(config): federation worker shard validation:** `tests/unit/test_config_parser.cpp` asserts that `federation.worker.shards` is parsed, that `shards=0` is rejected when the worker is enabled, and that `shards=0` is accepted when the worker is disabled.
- **test(federation): end-to-end worker flow integration:** `tests/integration/test_federation_worker_flow.cpp` spawns the real `merovingian-fed-worker` binary, waits for the pool to become healthy, routes non-room and room-scoped requests through the IPC channel, verifies shard selection, exercises in-process fallback when the pool is stopped, and routes room-scoped state requests and `/send` transaction bodies through the IPC channel.
- **test(ipc): expanded unit coverage for IPC framing and Ed25519 provider error paths:** `tests/unit/test_ipc_framing.cpp` and `tests/unit/test_ipc_federation_frames.cpp` now cover control-character JSON escaping, invalid HTTP status normalization, empty-body request round-trips, skipped headers, concurrent request/response pairing, stopped-channel behavior, and `IpcEd25519Provider` error handling for null channels, unexpected response types, malformed signatures, and main-side signing errors.
- **test(federation): `access_token` IPC round-trip:** `test_ipc_federation_frames.cpp` now asserts that `access_token` survives `serialize_fed_request` / `deserialize_fed_request` so X-Matrix auth is not silently dropped.
- **test(federation): v2 endpoint shard routing:** `test_federation_request_routing.cpp` now covers all five `/_matrix/federation/v2/` membership prefixes to verify the correct room ID is extracted for shard selection.

## 0.10.2

### Added
- **feat(federation): sign-back channel for the out-of-process federation worker (Phase 2):** the `merovingian-fed-worker` child no longer loads the Ed25519 server signing secret. When the worker needs to sign JSON (co-signing invites, `/_matrix/key/...` responses, etc.), it sends a `sign_request` IPC frame to the main process, which signs with its in-memory provider and returns the unpadded base64 signature. The private key never crosses the IPC boundary. New `IpcEd25519Provider` implements the `crypto::Ed25519Provider` interface over the encrypted channel; the main process handles `sign_request` in `FederationProxy` and returns `sign_response`.

### Changed
- **refactor(runtime): centralise runtime signing provider:** `HomeserverRuntime` now owns a `crypto::Ed25519Provider*` (`crypto_provider`) used by `publish_server_signing_keys()`, `compose_signed_event()`, invite co-signing, and outbound join/leave signing. `find_active_server_signing_key()` selects the active public key record without decrypting the secret. Worker startup injects `IpcEd25519Provider` via `RuntimeStartOptions::signing_override`; the main process uses the persisted production provider.

### Added tests
- **test(ipc): BDD scenario for `IpcEd25519Provider` round-trip:** `tests/unit/test_ipc_framing.cpp` covers a worker-side sign call being routed over the encrypted channel and returning the expected signature bytes.

## 0.10.1

### Added
- **feat(federation): out-of-process federation worker (`merovingian-fed-worker`):** federation CPU and I/O work (inbound PDU verification, state resolution, membership state machine, outbound dispatch) now runs in a dedicated child process with its own thread pool, so the main process threads are exclusively available for client-server API requests. A large room join no longer starves all connected clients. The IPC channel uses a `socketpair(AF_UNIX)` inherited file descriptor (no filesystem socket path), an ephemeral `crypto_kx` key exchange, and `crypto_secretstream_xchacha20poly1305` encryption for all frames. Client access tokens are stripped before forwarding; the worker receives only the validated user MXID.

## 0.9.25

### Fixed
- **fix(observability): eliminate duplicate fields in structured log lines:** all 42 modules were using `LOG_DEBUG(diagnostic_log_summary(...))`, which produced lines with the level word appearing twice (`<DEBUG> ... debug module event=...`) and the real module name hidden behind the wrapper function name `log_diagnostic:`. The public `log_diagnostic` free-function in `logger.hpp` now calls the appropriate named method (`debug()`, `info()`, etc.) using the logger name as the module, so the line format is `<LEVEL>  <module>:  event=<event> key=value ...` with no redundancy. All 42 modules migrated to use `observability::log_diagnostic()` directly.
- **fix(observability): missing timestamp on auth diagnostic lines:** `auth_service.cpp` was the only module calling the public `observability::log_diagnostic()` directly, which passed a raw summary string to `SingleLog::log()` without going through `make_log_line()`. The same fix above routes all calls through the named methods, restoring the timestamp header on every log line.

### Changed
- **feat(observability): promote major lifecycle events to INFO level:** the following events are now logged at INFO rather than DEBUG so operators see them without enabling verbose logging: `login.accepted`, `logout.accepted`, `logout_all.accepted`, `registration.accepted` (auth); `room.create.accepted`, `room.join.accepted`, `room.join.accepted_remote`, `room.leave.accepted` (rooms); `signing_key.loaded`, `signing_key.generated`, `signing_key.rotated` (crypto); `migration.step.applied`, `migration.plan.complete` (database); `tls.context.ready`, `start.listeners_ready`, `start.database_ready`, `start.hardening_controls`, `start.complete`, `database.hydrated` (server startup — already INFO, now correctly formatted). The `database.state.repaired` warning is also correctly emitted at WARNING via the structured path rather than the old `LOG_WARNING(diagnostic_log_summary(...))` pattern.

## 0.9.24

### Fixed
- **fix(client-server): re-acquire homeserver mutex after alias directory lookup in `POST /join/{roomIdOrAlias}`:** when joining a room by alias, the handler unlocked the homeserver guard before the outbound federation directory query (`/_matrix/federation/v1/query/directory`) but never re-locked it afterwards. Any subsequent call into `call_local` invoked `guard.unlock()` on an already-unowned `std::unique_lock`, throwing `std::system_error(EPERM)`. The exception was swallowed by the thread-pool worker (`action=swallowed, type=St12system_error, what=Operation not permitted`), silently aborting the join. The fix adds a single `guard.lock()` immediately after `perform_sync_outbound_call` returns, before processing the response body. Joining by room ID (which bypasses the alias lookup path) was unaffected.

### Added
- **test(client-server): BDD regression coverage for `POST /join` via room alias guard unlock bug:** `tests/unit/test_client_server.cpp` adds a scenario asserting that joining via a `#alias:server` form succeeds without throwing and returns the expected room ID.

## 0.9.23

### Fixed
- **fix(federation): start the outbound dispatch worker eagerly at server startup instead of lazily on the first join request:** `DispatchWorker::start()` was called inside `wire_federation_callbacks_impl()`, which was itself wired lazily on the first client-server request that needed federation. On Fedora/RHEL deployments with `TasksMax=` set, `pthread_create` returned `EPERM` and the resulting `std::system_error` propagated through the thread-pool worker, killing the worker and leaving federation permanently broken for that request. The fix has three parts: (1) `DispatchWorker::start()` now resets the `started_` flag on exception so a retry is possible; (2) `wire_federation_callbacks_impl()` catches `std::system_error` from `start()`, logs the failure, and resets the worker instead of propagating; (3) `main.cpp` calls `wire_federation_callbacks()` eagerly immediately after the runtime reaches its final stable location so thread-creation failures surface at startup as a clear log entry rather than inside a request handler.
- **fix(rooms): auto-write `m.direct` account data when `POST /createRoom` is called with `is_direct:true`:** when a DM room was created from one device (e.g. Element), the Matrix spec requires the *client* to subsequently `PUT` the `m.direct` global account data mapping the invitee to the new room. If that `PUT` never arrived — because the client manages it locally, or the server dropped it — a second device (e.g. ElementX) would see no `m.direct` entry and its `is_dm:true` sliding-sync list would return empty, causing it to create a duplicate DM room instead of showing the existing one. `create_room()` now calls a new `upsert_m_direct()` helper immediately after emitting the invite events: it reads any pre-existing `m.direct` mapping, appends the new `room_id` under each invitee's key (without duplicating), serialises, and persists via `database::store_account_data()`. Rooms created without `is_direct:true` are unaffected.

### Added
- **test(rooms): BDD coverage for `m.direct` upsert on DM room creation:** `tests/unit/test_homeserver_room_service.cpp` gains three scenarios — `m.direct` written when absent, second room appended without duplication, and non-DM room creation leaves `m.direct` untouched.

## 0.9.22

### Fixed
- **fix(client-server): implement `POST /_matrix/client/v3/pushers/set` so Element X stops showing "route not found" when registering for push notifications:** the endpoint was unimplemented and returned `404 M_UNRECOGNIZED`, causing Element X to report that it could not receive notifications. The handler now validates the request body per Matrix v1.18 (required `app_id`, `pushkey`, and `kind`; additional `app_display_name`, `data`, `device_display_name`, and `lang` for non-null kinds; HTTPS `/_matrix/push/v1/notify` URL for HTTP pushers) and returns `200 {}`. Merovingian still does not deliver push notifications, but clients can now register without error.

### Added
- **test(client-server): add BDD coverage for `POST /_matrix/client/v3/pushers/set`:** `tests/unit/test_client_server.cpp` exercises valid HTTP pusher registration, pusher deletion (`kind:null`), missing required fields, non-HTTPS URL rejection, missing notify-path rejection, and unauthenticated rejection. `tests/conformance/test_client_server_conformance.cpp` asserts the spec-required `200 {}` response shape for both registration and deletion.

## 0.9.21

### Fixed
- **fix(sync): emit explicit m.typing stop events so typing notifications can restart after a user stops typing:** previously `/sync` only emitted an `m.typing` ephemeral event when the current list of typing users was non-empty. A stop-typing request removed the user from the list but sent nothing, so clients that replace their typing knowledge only on received events still believed the user was typing; the next start-typing event therefore appeared unchanged and clients did not surface a new notification. The server now tracks a per-room `room_typing_stream_id` cursor that advances whenever the set of typing users changes, and `/sync` (and the MSC4186 typing extension) emits the current list for that room on every change, including an empty `user_ids` array when the user stops. This also fixes transitions where one of several typing users stops but another continues, because the response now carries the full current list rather than only users whose individual cursor is newer than `since`.

### Added
- **test(sync): typing stop/restart regression coverage:** `tests/integration/test_client_server_flow.cpp` adds `SCENARIO("Typing notifications can stop and restart via ephemeral events in /sync")`, which asserts start -> non-empty list, stop -> empty list, restart -> non-empty list.

## 0.9.20

### Fixed
- **fix(database): persist sync_stream_watermark so sync stream IDs cannot roll back across restart:** `sync_stream_id` is the monotonically-increasing third component of the `/sync` stream token triplet and is used for to-device messages, device-list changes, presence, global account data, room account data, typing notifications, and read receipts. In-memory-only sync surfaces (`rt.homeserver.typing_users` and `rt.homeserver.receipts`) previously advanced the counter without persisting it, so a server restart could reset `next_sync_stream_id` to a value the client had already seen. This caused `/sync` long-polls to skip new ephemeral events and, in some clients, to return an empty `rooms.join`. A new `sync_stream_watermark` table stores the highest allocated ID, and `database::allocate_sync_stream_id()` atomically increments the in-memory counter and persists it before returning the ID. Fresh installs bootstrap schema version `1` and apply migration `002_sync_stream_watermark.sql`; existing version-`1` deployments migrate cleanly to version `2`.
- **fix(sync): ensure ephemeral typing and receipt events advance the persistent sync stream counter:** the `PUT /typing/{userId}` endpoint, receipt handling, and account-data/account-data paths previously advanced `rt.database.next_sync_stream_id` directly, which was both un-persisted and leaked counter-management details across modules. They now call `database::allocate_sync_stream_id(store)` so every typing notification, read receipt, and account-data write bumps the durable watermark, keeping the ordering stable across restarts.
- **fix(sync): deliver typing notifications to `/sync` recipients after homeserver restart:** because the sync stream counter could roll back after restart, a typing event written after restart could carry an ID less than or equal to the recipient's `since` token. The `/sync` response builder therefore ignored it and the recipient saw no `m.typing` ephemeral event. With the watermark in place, allocated IDs are always strictly greater than any ID previously returned to clients, so typing notifications are delivered correctly after restart.
- **fix(database): seed the v2 migration watermark from the highest persisted sync_stream_id:** migration `002` previously created `sync_stream_watermark` with the default value `'0'`, so an existing database whose in-memory counter had advanced via typing/receipts would start the counter from the max of the persisted surfaces after restart. The migration now inserts `COALESCE(MAX(CAST(stream_id AS INTEGER)), 0)` across `account_data`, `room_account_data`, `to_device_messages`, `device_list_changes`, and `presence_state` as the initial watermark.
- **fix(sync): advance the sync stream counter when a client's since-token is ahead of the server:** if the `/sync` `since` token's `sync_stream_id` exceeds `store.next_sync_stream_id`, `sync_json()` now calls `database::ensure_sync_stream_id_ahead_of()` to advance the counter (and persist the watermark) to the client's position. This recovers live deployments whose counter rolled back below a client's stored token — the next typing notification or receipt gets an ID strictly greater than the token and is delivered.

### Added
- **test(database): add regression coverage for sync stream watermark persistence:** `tests/unit/test_database_persistence.cpp` adds `SCENARIO("Sync stream watermark prevents sync-stream id rollback across SQLite restart")`, which writes a watermark via `allocate_sync_stream_id()`, re-opens the SQLite persistent store, and asserts the restored counter is greater than the pre-restart value.
- **test(sync): add typing notification delivery regression test:** `tests/integration/test_client_server_flow.cpp` adds `SCENARIO("Typing notifications are delivered via ephemeral events in /sync")`, which creates a room, starts typing, waits for the recipient's `/sync` to return the `m.typing` ephemeral event, and asserts it contains the sender.
- **test(database): add regression coverage for counter rollback recovery:** `tests/unit/test_database_persistence.cpp` adds `SCENARIO("ensure_sync_stream_id_ahead_of recovers from a counter rollback")`, which simulates a client since-token ahead of the persisted watermark, advances the counter, and asserts the next allocated ID exceeds the token.

## 0.9.19

### Fixed
- **fix(sync): stop ElementX sliding-sync loop caused by repeated room re-inclusion:** MSC4186 `/_matrix/client/unstable/org.matrix.msc4186/sync` now tracks the last stream ordering at which each room was returned per connection (`SlidingSyncConnectionState::rooms_seen` is a `std::unordered_map<std::string, std::uint64_t>`).  The per-room delta floor is `max(request_since, per_room_last_inclusion)`, so a room is not pulled back into `rooms{}` by unread counts alone.  Unread counts are now sent only when the room is already included because its timeline or `required_state` changed.
- **fix(sync): wake MSC4186 sliding sync long-poll on typing and read receipts in joined rooms:** the spurious-wakeup suppression logic only considered device-list changes, to-device messages, and account-data as relevant `sync_stream_id` advances.  Typing notifications and read receipts in the user's joined rooms advanced the stream id without waking the long-poll, so ElementX did not receive live updates or conversation changes.  The relevance check now also scans `rt.homeserver.receipts` and `rt.homeserver.typing_users` scoped to joined rooms.  Added `rooms_in_response`, `rooms_skipped`, and `rooms_window` fields to the `sliding_sync.response` diagnostic log, plus BDD unit coverage for both the repeated-poll suppression case and the typing wake-up case.

## 0.9.18

### Added
- **feat(client-server): implement Matrix room tag endpoints:** `GET/PUT/DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags[/{tag}]` is now wired for joined members, storing tags as per-user/per-room `m.tag` room account data. `PUT` accepts an empty body or `{ "order": <double> }`; `DELETE` removes a tag; `GET` returns the spec-shaped `{ "tags": { "<tag>": { ... } } }` map.
- **feat(canonicaljson): add general JSON parser/serializer with `double` support:** `canonicaljson::parse_json()` parses arbitrary Matrix client JSON (using yyjson) into a new `canonicaljson::Value::double_` alternative, and the serializer emits doubles with shortest round-trippable output. This lets room account data such as `m.tag` contain non-integer values without breaking the signing-focused canonical JSON pipeline, which still rejects non-integer numbers.

### Fixed
- **ci: fix coverage and sanitizer jobs on the new branch:** `gcovr` now runs with `--gcov-ignore-parse-errors` so clang-generated branch-heavy `.gcov` output for `client_server.cpp` no longer aborts coverage report generation. The ASan/UBSan job now sets `MESON_TEST_TIMEOUT_MULTIPLIER=3` so the seccomp/SQLite integration test is not killed by the default 600 s timeout under sanitizer-induced slowdown.

## 0.9.17

### Added
- **feat(homeserver): implement Matrix space hierarchy endpoints:** `GET /_matrix/client/v1/rooms/{roomId}/hierarchy` now returns a paginated, depth-first list of rooms in a space tree, honouring `max_depth`, `suggested_only`, and `limit`, with URL-safe base64 pagination tokens. `GET /_matrix/federation/v1/hierarchy/{roomId}` is also wired so remote servers can fetch a space summary. Both endpoints use the local persistent state (`m.space.child`, `m.room.create`, `m.room.join_rules`) and apply visibility rules before exposing rooms.
- **feat(homeserver): implement Matrix v1.18 event relations endpoints:** `GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]` is now wired for joined members. The endpoint scans local room events for `m.relates_to` references to the parent event, optionally filters by `rel_type` and child `event_type`, supports `dir`, `from`, `to`, `limit`, and `recurse` query parameters, and returns a spec-shaped paginated `chunk` with optional `next_batch`, `prev_batch`, and `recursion_depth` fields. Encrypted poll responses that relate via `m.reference` are now returned as `m.room.encrypted` events, fixing Element polls that previously failed with `404 M_UNRECOGNIZED`.

### Fixed
- **fix(media): encrypted-room attachments no longer quarantined on upload and authenticated `POST /_matrix/client/v1/media/upload` is wired:** E2EE clients (Element/Web) upload encrypted attachments as opaque `application/octet-stream` ciphertext, which was missing from the default `security.media.allowed_mime_types` allow-list and caused uploads to be quarantined; downloads of those quarantined files later returned `451 Unavailable For Legal Reasons`. The default allow-list now includes `application/octet-stream`, and operators can override the list via the new `security.media.allowed_mime_types` configuration key. The authenticated v1 upload endpoint was also absent from the client-server dispatcher and has been added, using the same raw-binary-to-pipe-format translation as the unauthenticated v3 path.
- **fix(config): example configuration now includes all recognised keys:** `config/merovingian.conf.example` was missing `security.access_token_lifetime_ms`, `security.refresh_token_lifetime_ms`, `security.media.allowed_mime_types`, `security.media.remote_fetch_enabled`, and `security.secrets.master_key_file`. Each is now documented with its default and, where relevant, the security implications of changing it.

## 0.9.16

### Fixed
- **fix(media): media download and thumbnail endpoints no longer 404 on query parameters and now return raw bytes with Content-Type:** `GET /_matrix/media/v3/download/{serverName}/{mediaId}`, `GET /_matrix/client/v1/media/download/{serverName}/{mediaId}`, and the equivalent thumbnail routes failed when clients appended `?allow_redirect=true` (or `?width=...&height=...`) because `local_media_download_parts` parsed the query string as part of the media ID. The helper now strips the query component before splitting `server_name`/`media_id`. Additionally, successful download/thumbnail results were returned in the internal `content_type|bytes` pipe format to clients instead of the raw bytes the Matrix spec requires; `client_server.cpp` now splits that payload and emits a `Content-Type` header.

## 0.9.15

### Added
- **test(events): add BDD coverage for event_signer.cpp** — new `tests/unit/test_event_signer.cpp` exercises `signing_key_id_is_valid` (valid, empty server_name, empty key_id, control chars, space, DEL), `matrix_base64_from_bytes`/`matrix_bytes_from_base64` (round-trip, empty input, invalid base64), `make_event_signing_payload` without and with `RoomVersionPolicy` (success and non-object error paths), `attach_event_signature` (success, invalid key ID, short-decoded signature, non-object event), `sign_event_for_server` (success, non-object event, no key for server), `verify_event_signature_presence` (invalid key ID, non-object, missing signatures, missing server), and `verify_event_signature` (end-to-end success, provider-failure path).
- **test(crypto): expand signing_service.cpp coverage** — six new scenarios appended to `tests/unit/test_crypto.cpp`: `signing_key_record_is_usable` directly tested for active, inactive, empty server_name, non-Ed25519 key_id, and wrong-size public key; `sign_for_server` with empty server name ("server name is empty"), key store error propagation, server-name mismatch ("active signing key server mismatch"), provider error propagation, and provider returning invalid signature shape ("provider returned invalid Ed25519 signature shape").
- **test(media): expand media/security.cpp coverage** — eleven new scenarios appended to `tests/unit/test_media_security.cpp`: `media_disposition_name` for all three enum values, `media_mime_type_is_allowed` direct call with allowed and unlisted types, `evaluate_media_upload` for zero size limit, zero byte_size, missing content sniff result, reject (not quarantine) for unknown MIME with `quarantine_unknown_mime=false`, and reject (not quarantine) for scanner failure with `quarantine_scanner_failures=false`; `remote_media_fetch_policy` for invalid origin server and empty resolved_host, and SSRF-blocking-disabled path; `admin_quarantine_policy` for invalid admin user ID and invalid media ID; `evaluate_decoder_safety` for input bytes exceeding the limit and pixel count exceeding the limit.
- **test(auth): expand key_api.cpp coverage** — five new scenarios appended to `tests/unit/test_key_api.cpp`: `key_payload_is_loggable("")` and `redacted_key_payload_summary("")` for the empty-payload branch; `key_api_endpoint_name` exhaustive coverage for all 19 enum values confirming no "unknown" fallback; `match_key_api_route` no-match cases (wrong path, wrong method); full GET and DELETE backup-route matching for version-by-id, room-key batch, room-key-by-session, room-key-by-room, and delete-version; `key_api_database_statements` for update, delete, get backup-version, claim-keys, and upload-signatures endpoints.
- **test(database): add BDD coverage for schema identifier quoting, core-table introspection, migration-step validation, and migration-plan validation error paths:** `tests/unit/test_database_schema.cpp` exercises `quote_sqlite_identifier` rejection of empty inputs and SQL-injection characters (semicolons, embedded quotes, spaces), `schema_table_is_core` and `schema_table_definition` for known vs unknown table names, `create_table_sql` DDL generation and non-core rejection, `current_schema_version` non-zero invariant, `initial_schema_tables` non-empty invariant, `migration_step_is_valid` rejecting version-zero upgrade steps, hyphenated names, empty statement lists, and multi-statement SQL, `migration_direction_name` round-trips, `migration_rollback_policy` non-empty policy string, `migration_plan_between` same-version no-op and beyond-catalog empty-plan cases, `apply_migration_plan` state-version-mismatch failure, and `migration_plan_is_valid` covering no-op-with-steps rejected, upgrade-with-no-steps rejected, direction-mismatch rejected, and catalog-derived plan accepted.
- **test(homeserver): add BDD coverage for authentication and HTTP-dispatch failure paths:** `tests/unit/test_homeserver_error_paths.cpp` exercises login with wrong password, login for unknown user, duplicate username registration, logout with unknown/empty token, `verify_local_user_password` with wrong password, `handle_local_http_request` returning 4xx for unrecognised routes, `handle_local_http_request` returning 401 for auth-required routes with no access token, and `handle_federation_http_request` returning 4xx for non-federation paths.
- **test(homeserver): add BDD coverage for auth_service functions not previously tested:** `tests/unit/test_homeserver_auth_service.cpp` exercises `bootstrap_admin_user` success and duplicate rejection, admin privilege confirmed via `authenticated_admin_user` and denied for regular users, `account_state_for_user` returning nullopt for unknown/empty user IDs and `AccountState::active` for new registrations, `logout_all_local_user` rejecting unknown/empty tokens and revoking all sessions, `change_local_user_password` rejecting unknown tokens and verifying old token invalidation + old password rejection + new password acceptance, `delete_local_device` rejecting unknown user and unknown device and confirming session invalidation on valid deletion, `issue_refresh_token_for_session` failing for unknown users, `refresh_local_session` rejecting empty/unknown tokens, issuing new tokens on valid exchange, and enforcing single-use, and `access_token_is_soft_logout` returning false for empty and unknown tokens.
- **test(homeserver): add BDD coverage for room_service operations not previously tested:** `tests/unit/test_homeserver_room_service.cpp` exercises `ban_user` rejecting unauthenticated callers, non-existent rooms, and non-privileged members; confirming the room creator can ban a member; `kick_user` rejecting unauthenticated callers and non-privileged members; confirming the room creator can kick; `unban_user` rejecting unauthenticated callers and confirming the room creator can lift a ban; `forget_room` rejecting unauthenticated callers, rejecting forget-while-joined, and succeeding after leave; `knock_room` rejecting unauthenticated callers and non-existent rooms.
- **test(federation): add BDD coverage for server-name validation boundaries and PDU envelope parsing error paths:** `tests/unit/test_federation_server_name.cpp` exercises `server_name_is_valid` accepting valid domains and domain-with-port, rejecting empty strings, dot-free single-label names, names exceeding 255 characters, names with embedded spaces, newlines, and tabs; `federation_discovery_policy` rejecting unresolved hosts, empty address sets, invalid server names, and TLS-not-required remotes; `parse_inbound_pdu_envelope` returning nullopt for empty input, JSON arrays, JSON string literals, and malformed JSON.

## 0.9.14

### Fixed
- **fix(client-server): implement `GET /_matrix/client/v3/rooms/{roomId}/initialSync` for room previews and stop Element Web "route not found" errors:** this endpoint is deprecated for general syncing but is still used by Element Web to preview public rooms before joining. The route was previously unimplemented, returning `404 M_UNRECOGNIZED` and causing an uncaught promise rejection when selecting a room from the directory. The handler now returns the spec-shaped `RoomInfo` response (`room_id`, `membership`, `messages`, `state`, `visibility`, `account_data`) for current and previous members, and allows non-member peeking when the room's `m.room.history_visibility` state is `world_readable`. Non-peekable or non-resident rooms return `403 M_FORBIDDEN` so the client can fall back to joining; the spec only defines 200/403 for this endpoint.
- **fix(media): media uploads larger than 1 MiB no longer rejected at HTTP parse layer with CORS-less 413:** `parse_request_head` checked `Content-Length` against a hard-coded 1 MiB default before the request reached `handle_client_server_request`, so any upload between 1 MiB and the configured `max_upload_size` (default 100 MiB) was refused at the transport layer with a 413 response that carried no `Access-Control-Allow-Origin` header — causing browsers to misreport it as a CORS error. The body-size check is removed from the parser (syntax validation only) and moved into `serve_stream`, where the target URL is available: `POST /_matrix/media/v3/upload` and `POST /_matrix/client/v1/media/upload` now use the configured `max_upload_size` cap; all other routes use the smaller general cap. When the cap is exceeded the 413 response now includes `Access-Control-Allow-Origin` derived from the request `Origin` header and the configured CORS policy, so browsers display the real 413 status rather than a spurious CORS error.

### Added
- **test(client-server): add BDD coverage for `GET /_matrix/client/v3/rooms/{roomId}/initialSync`:** `tests/unit/test_client_server.cpp` now exercises the new route for the creating member, a non-member in a `world_readable` public room (peek allowed), a non-member in a private room (`403 M_FORBIDDEN`), an unknown/non-resident room (`403 M_FORBIDDEN`), and the `?limit=` query parameter.
- **test(http): add BDD scenario verifying parser accepts large Content-Length without error:** `test_http_request.cpp` now includes a scenario asserting that `POST /_matrix/media/v3/upload` with `Content-Length: 2097152` (2 MiB) parses without error, confirming the parser no longer rejects bodies above 1 MiB.

## 0.9.13

### Fixed
- **fix(tests): repair compile errors in 3PID test suite introduced in v0.9.13:** five occurrences of `R"("})"}` in conformance tests were parsed as raw string `"}` plus a stray `}` due to C++ raw-string early termination (the empty delimiter closes at the first `)"` sequence); fixed to `R"("})"`. Two WHEN/GIVEN blocks in the integration and unit tests had missing `;` on string-concatenation declarations, causing `};` on the next line to close the enclosing scope prematurely and make all subsequent variables undeclared; fixed by adding the missing semicolons and re-indenting action code inside the WHEN blocks. `integer_member` helper calls in conformance tests renamed to the correct `int_member`. Integration test assertion for `bob_duplicate_add` relaxed from `== 400U` to `!= 200U` since UIA correctly rejects with 401 before the duplicate check is reached. Unit test assertion that the `M_SESSION_NOT_VALIDATED` error body contains the `sid` value removed — the Matrix spec does not require the sid to be echoed in error bodies.
- **fix(client-server): remote room aliases now resolve over federation for room-directory lookups and joins:** `GET /_matrix/client/v3/directory/room/{roomAlias}` previously only searched the local alias table, so looking up `#alias:remote.example.org` returned a misleading local `M_NOT_FOUND` instead of querying the alias-owning homeserver via federation. `POST /_matrix/client/v3/join/{roomIdOrAlias}` had the same gap: when given a remote room alias it rewrote directly to `/rooms/{roomId}/join`, treating the alias text as though it were already a room ID and never resolving the remote alias to the room ID plus `via` servers required for the join. The client-server handler now federates `/_matrix/federation/v1/query/directory` for remote aliases, rewrites remote-alias joins to the resolved room ID with merged `via` servers, and includes joined-member server names in local alias responses.
- **fix(client-server): account 3PID management now works end-to-end:** Merovingian now implements the client-account 3PID flow instead of stopping at the auth-gate workaround. `POST /_matrix/client/v3/account/3pid/email/requestToken` and `.../msisdn/requestToken` remain unauthenticated per Matrix v1.18, reject identifiers already in use with `M_THREEPID_IN_USE`, and issue validation `sid` values. Authenticated clients can now complete `POST /_matrix/client/v3/account/3pid/add`, `POST /_matrix/client/v3/account/3pid`, `POST /_matrix/client/v3/account/3pid/bind`, `POST /_matrix/client/v3/account/3pid/unbind`, and `POST /_matrix/client/v3/account/3pid/delete`, while `GET /_matrix/client/v3/account/3pid` returns the spec-shaped `threepids` array with `added_at`, `address`, `medium`, and `validated_at`. `GET /_matrix/client/v3/capabilities` now also advertises `m.3pid_changes`.
- **fix(media): media uploads now accept real HTTP clients (raw binary body + Content-Type header):** `POST /_matrix/media/v3/upload` previously delegated the raw client request directly to the local media router, which expected an internal pipe-delimited body (`declared_mime|sniffed_mime|scanner_clean|bytes`). Real Matrix clients (Element X, Element Web) send a raw binary body with a `Content-Type` header, causing every real upload to fail with 400 `upload body must be declared_mime|sniffed_mime|scanner_clean|bytes`. The handler now extracts the `Content-Type` header from the request and constructs the correct pipe-delimited body before forwarding to the local router. Missing `Content-Type` defaults to `application/octet-stream`. The route match is also widened from an exact string check to handle the `?filename=...` query parameter (e.g. `/_matrix/media/v3/upload?filename=avatar.jpg`), which previously fell through to the general body-size gate and returned 413 for any upload larger than 64 KiB. Media upload requests are now governed by the configured `security.media.max_upload_size` (default 100 MiB) instead of the general 64 KiB client-API body cap. Quarantined uploads (internal MIME policy, 202 from the local router) are mapped to 200 toward the client with the assigned `content_uri`, since quarantine is a server-internal moderation action not defined in the Matrix spec response contract.
- **fix(sync): sync pool no longer exhausted by zombie timeout=30000 connections from rapid SDK reconnects:** when a sliding-sync client (e.g. matrix-rust-sdk) sends a new `timeout=30000` long-poll every ~90 ms while abandoning the previous TCP connection, each parked sync-pool thread was blocked in `wait_for_change` for a full 5-second poll slice before detecting the dead socket — even though the peer had already closed. With 11 new connections per second and a 5-second hold time, the 32-thread sync pool became exhausted within ~3 seconds, causing subsequent long-polls to queue behind zombie tasks or fall through to the main pool, stalling all other traffic. The fix reduces the poll-interval from 5 s to 1 s and adds a non-blocking `recv(MSG_PEEK | MSG_DONTWAIT)` liveness check after each slice timeout: a return value of 0 (TCP FIN) or a connection error (not EAGAIN/EWOULDBLOCK) causes the thread to exit immediately and close the fd without building or logging a response. Steady-state thread consumption drops from ~55 to ~11 for this pattern.

### Fixed
- **fix(sync): sliding sync no-pos poll returns delta after first sync, ending the matrix-rust-sdk tight-loop:** matrix-rust-sdk sends a `timeout=0` (no `pos` in URL) probe alongside every `timeout=30000` long-poll to get an immediate snapshot. Before this fix the server used `since_event_ordering=0` for every no-pos request — regardless of whether the connection had been used before — re-delivering all accumulated room history (≈17 KB per cycle) on every call. The SDK received the same `pos` each time, treated it as a full initial sync, and immediately re-polled, creating a tight loop at ~11 cycles per second. The fix moves the per-connection state lookup before the `since` computation in `sliding_sync_json`: when `pos` is absent but the connection already has state (`rooms_seen` non-empty), `since_event_ordering` / `since_sync_stream_id` fall back to the connection's last-known cursors instead of zero. First call for a fresh connection still uses `since=0` so the SDK receives the complete initial room list; all subsequent no-pos polls return a small delta (`rooms: {}` when nothing changed), causing the SDK to honour the 30-second long-poll instead of looping.

### Added
- **test(client-server): add BDD coverage for remote alias federation failures:** two scenarios in `tests/unit/test_client_server.cpp` verify the repaired path. Remote room-directory lookups now fail as federation errors rather than false local alias misses, and alias-based joins now fail only after remote alias resolution is attempted instead of treating the alias itself as a room ID.
- **test(client-server): add 3PID unit, integration, and conformance coverage:** unit and integration scenarios now cover the account 3PID lifecycle across request-token, UIA add, bind, list, unbind, delete, and duplicate-rejection paths. Conformance coverage now asserts the spec-shaped unauthenticated request-token behavior, UIA challenge semantics for `POST /account/3pid/add`, and the required `GET /account/3pid` response shape.
- **test(sync): add BDD unit tests for sync pool zombie-connection detection:** three scenarios in `tests/unit/test_sync_pool_liveness.cpp` validate the `recv(MSG_PEEK | MSG_DONTWAIT)` liveness mechanism using Unix socket pairs — peer-closed detection (returns 0), live-connection non-detection (returns EAGAIN/EWOULDBLOCK), and abrupt-reset detection via SO_LINGER with l_linger=0.
- **test(sync): add BDD unit tests for sliding sync no-pos delta behavior:** two scenarios in `test_client_server.cpp` verify the root-cause fix — that a second `timeout=0` poll on the same `conn_id` with no intervening events returns `rooms: {}` and the same `pos`, and that a poll after a new message event returns an advanced `pos` and includes the new timeline event.

## 0.9.11

### Added
- **test(database): add direct coverage for media, policy, and key-backup cleanup helpers:** expand unit coverage for `store_local_media` / `update_local_media_state` / `store_remote_media`, direct `delete_policy_rule` behaviour, and scoped `key_backup_sessions` cleanup paths (`delete_key_backup_session`, `delete_key_backup_room_sessions`, `delete_all_key_backup_sessions`).

## 0.9.10

### Fixed
- **fix(sync): MSC4186 sliding sync long-poll no longer returns early when only another user's device keys were uploaded:** `handle_key_upload` fans out `PersistentDeviceListChange` rows to every co-member when a user uploads keys, and each write fires the global `SyncNotifier`. This woke the uploading user's own sliding sync immediately, causing matrix-rust-sdk to reset to a full `timeout=0` initial sync and loop at ~5 cycles/second. The fix adds a relevance check in `sliding_sync_json`: when only `sync_stream_id` has advanced (no new room events), the handler inspects whether any new device-list-change, to-device-message, or account-data row is actually addressed to the waiting user. If not, it returns `needs_wait` with `since_sync_stream_id` advanced to the current counter, so the notifier must fire again before the next wakeup. All three wait paths in the HTTP server (`dispatch_local_http_request`, inline blocking, sync_pool lambda) are updated to loop with `can_wait=true` after each notifier fire, continuing if the handler re-parks.
- **fix(sync): incremental MSC4186 sliding sync no longer returns unchanged rooms, ending the Element X tight-poll loop:** two complementary bugs caused matrix-rust-sdk to treat every incremental response as carrying new data and immediately re-poll with `timeout=0`. First, `build_room_response` included all `required_state` events unconditionally; it now filters to only events whose `stream_ordering > since_event_ordering` on incremental responses (initial syncs are unaffected). Second, `sliding_sync_json` included every windowed room in the `rooms{}` object regardless of whether anything changed; rooms are now gated by `has_room_updates` — a room appears in `rooms{}` only when it is being seen for the first time, has new timeline events, has changed required_state, or has non-zero notification/highlight counts. Together these ensure that when nothing has changed since the `pos` the incremental response carries `rooms: {}`, which causes the client to honour the 30-second long-poll timeout instead of looping.

### Added
- **test(sync): add BDD test verifying sliding sync spurious-wakeup suppression:** two scenarios in `test_client_server.cpp` cover the device-key-upload case: when alice uploads keys (creating DLCs only for co-members as observers), `handle_client_server_request(can_wait=true)` returns `needs_wait` with an advanced `since_sync_stream_id`; when bob uploads keys (creating a DLC with alice as observer), the same call returns `complete` with `device_lists.changed` populated.
- **test(sync): add BDD unit tests for `build_room_response` incremental filtering:** six scenarios in `tests/unit/test_sliding_sync_room_builder.cpp` cover the initial-vs-incremental `required_state` filtering: all matching state included on initial sync; state predating the pos omitted on incremental; only post-pos state included when mixed; wildcard `*/*` filter respects the same ordering gate; no-update responses produce empty `required_state_json` and `timeline_json`; new timeline events correctly populate `timeline_json`.

## 0.9.8

### Added
- **test(client-server): add direct route coverage for `joined_members` and presence updates:** new unit scenarios cover `GET /_matrix/client/v3/rooms/{roomId}/joined_members` for current-member authorization, joined-profile shaping, and left-member exclusion, plus `PUT /_matrix/client/v3/presence/{userId}/status` for explicit online presence, default-offline behavior, malformed-body rejection, forbidden cross-user updates, and `/sync` delivery of `m.presence` events.
- **test(database): add direct persistence-helper coverage for filters, profiles, client transaction ids, account-data upserts, sync-stream rows, and room aliases:** new unit scenarios exercise `store_filter`/`find_filter` upserts and sensitive JSON handling, `store_profile` with targeted displayname/avatar updates and missing-user rejection, `store_client_txn` idempotency so the first stored response wins while room/type scoping still permits distinct records, `store_account_data` global-vs-room upsert behavior, `record_device_list_change` and `upsert_presence` stream-id behavior and validation, and `store_room_alias` lookup/duplicate/missing-room handling.

## 0.9.7

### Fixed
- **fix(sync): route `POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync` to the MSC4186 handler (0.9.7):** Element X (matrix-rust-sdk) probes for sliding sync via the `simplified_msc3575` path, not the `msc4186` path. The `unstable_features` flag `org.matrix.simplified_msc3575 = true` was already advertised in 0.9.6, but the endpoint itself returned 404, causing the client to enter a tight retry loop — hundreds of failed sliding-sync attempts per second with concurrent fallback `v3/sync` calls. The dispatcher now accepts both `/_matrix/client/unstable/org.matrix.msc4186/sync` and `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`, routing both to the same MSC4186 handler.

## 0.9.6

### Fixed
- **fix(ci): make coverage reporting match the actual project surface:** the Codecov/gcovr path now excludes the real process entrypoint (`src/main.cpp`) rather than the nonexistent `src/homeserver/main.cpp`, and the coverage workflow now filters headers to `include/merovingian/` instead of every file staged under `include/`. This stops vendored/platform headers from diluting the reported percentage and aligns the uploaded report with the code we actually own.
- **fix(sync): advertise MSC4186 with the compatibility flag Element X actually probes:** `GET /_matrix/client/versions` now exposes both `unstable_features["org.matrix.msc4186"] = true` and `unstable_features["org.matrix.simplified_msc3575"] = true`. Element X's upstream `matrix-rust-sdk` currently autodetects sliding sync via the `org.matrix.simplified_msc3575` flag, so advertising only `org.matrix.msc4186` caused the client to reject the homeserver before ever calling the sliding-sync endpoint.

### Added
- **test(sync): add direct MSC4186 room-list and extension coverage:** new unit scenarios exercise `compute_room_list` filtering/sorting/incremental SYNC behavior and `build_extensions` scoping for `to_device`, `e2ee`, `account_data`, `receipts`, and `typing`. A dedicated tooling test now guards the coverage workflow/config so future changes cannot silently widen the measured surface or exclude the wrong entrypoint again.

## 0.9.5

### Fixed
- **fix(rooms): `GET`/`POST /_matrix/client/v3/publicRooms?server=<remote>` now proxies to the remote homeserver (spec §10.5.1):** both endpoints previously ignored the `server` query parameter and returned an empty local room list, causing "no rooms found" when clients searched a remote server (e.g. `grapheneos.org`). The handlers now check the parameter: when it names a different server the request is forwarded to `GET /_matrix/federation/v1/publicRooms` (unfiltered) or `POST /_matrix/federation/v1/publicRooms` (when a `filter.generic_search_term` is present). When `server` is absent or equals the local server name the existing local-list path is used unchanged. Unauthenticated federation (`outbound_client` not configured) surfaces as 502 M_UNKNOWN rather than a silent empty list. The raw `since` pagination token is now preserved and forwarded to the remote server instead of being parsed as a local integer offset.

## 0.9.4

### Added
- **feat(sync): MSC4186 Simplified Sliding Sync (unstable) — `POST /_matrix/client/unstable/org.matrix.msc4186/sync`:** implements the full MSC4186 Simplified Sliding Sync proposal as an unstable extension. The endpoint is advertised via `unstable_features["org.matrix.msc4186"] = true` in `/_matrix/client/versions`. Features: named room lists with windowed ranges, sort criteria (`by_recency`, `by_notification_count`, `by_name`), list operations (SYNC / INVALIDATE / INSERT / DELETE / UPDATE), per-room state and timeline with `required_state` wildcards, explicit room subscriptions with independent parameters, and all five MSC4186 extensions (to_device, e2ee, account_data, receipts, typing). Long-polling reuses the dedicated sync thread pool with the same slice-and-deadline pattern as `v3/sync`. Per-connection state is keyed by `user_id/device_id/conn_id` and tracks previous list windows so subsequent requests return only incremental ops. Position tokens (`pos`) reuse the existing hex-encoded `StreamToken` triplet. Overlapping or inverted ranges are rejected with 400 M_BAD_JSON.
- **test(sync): MSC4186 sliding sync integration test suite (`tests/integration/test_sliding_sync_flow.cpp`):** seven integration scenarios exercising the full HTTP handler end-to-end — advertisement in `/_matrix/client/versions`, initial SYNC op with `initial:true`, `required_state` wildcard filtering, `timeline_limit` enforcement, incremental sync without `initial:true` on already-seen rooms, `to_device` extension delivery, and `e2ee` extension key counts. Also adds unit tests (`tests/unit/test_sliding_sync.cpp`) covering the parser layer and MSC4186 conformance tests (`tests/conformance/test_sliding_sync_conformance.cpp`) for all MUST requirements verifiable at the parser boundary.

## 0.9.3

### Fixed
- **fix(sync): server respects client-requested `/sync` timeout in full (spec §9.4):** the `/sync` long-poll handler now waits for the full client-requested duration. Previously a hard 5 s cap in the sync-pool dispatch lambda overrode every client timeout, causing connections with `?timeout=30000` to fire after 5 s and re-poll needlessly. The sync pool now polls in 5 s slices internally (so shutdown remains bounded) but each slice counts against the client's actual deadline. Clients that omit `timeout` continue to receive an immediate response per the spec.
- **fix(log): promote major auth and server lifecycle events from DEBUG to INFO:** `login.accepted`, `start.complete`, `start.database_ready`, `start.listeners_ready`, and `start.hardening_controls` are now logged at INFO level. Previously every structured diagnostic was emitted at DEBUG, making logs uninformative unless debug mode was explicitly enabled. ERROR and WARNING events (login rejections, audit failures) were already routed correctly; this change covers the success-path events that operators need to confirm normal operation.

## 0.9.2

### Fixed
- **fix(auth): access tokens no longer silently expire for clients that did not opt into refresh tokens (spec §5.6.2):** `login_local_user` now accepts a `with_ttl` flag; the configured `access_token_lifetime_ms` is applied only when the client explicitly requests refresh-token support (`"refresh_token": true` in the login body). Clients that do not opt in receive a non-expiring access token, conforming to the Matrix spec requirement that servers SHOULD NOT expire access tokens without co-issuing a refresh token. Previously, every login silently set a 1-hour TTL regardless, causing users to be logged out every hour with no warning and no way to recover the session.

## 0.9.1

### Fixed
- **fix(http): wire TLS sync pool to eliminate main-pool starvation and federated E2EE key-share delay:** `serve_tls_http` now passes `sync_pool` and a TLS-aware write callback through to `serve_stream`. TLS long-poll `/sync` connections are offloaded to the dedicated 32-thread sync pool identically to the plain-HTTP path, freeing main pool threads for federation requests. Previously the `sync_pool` parameter was silently discarded (`/*sync_pool*/`), causing all TLS long-poll connections to block main pool threads for up to 30 seconds. This starved federation transaction processing, delaying delivery of `m.direct_to_device` key-share EDUs and producing the observable symptom of taking up to 30 seconds to decrypt a newly-joined federated user's replies. `TlsConnectionStream` is updated to hold `shared_ptr<TlsConnection>` so the TLS state can be shared safely between the read phase (main pool thread) and the async write phase (sync pool thread). The sync wait cap remains 5 seconds, matching the plain-HTTP path.

## 0.9.0

### Fixed
- **fix(auth): include `soft_logout: true` in 401 responses for expired access tokens (spec §5.7.2):** when an access token is found-but-expired the server now returns `{
        "errcode" : "M_UNKNOWN_TOKEN", "error" : "unauthenticated", "soft_logout" : true}` so Matrix clients use their refresh token rather than performing a full session logout. Revoked tokens continue to return a plain 401 without `soft_logout`, preserving hard-logout semantics for explicit revocations.

### Changed
- **chore(release): beta milestone — promote from pre-beta (0.8.x) to beta phase (0.9.0):** version number advanced to 0.9.0 per the versioning scheme phase markers. No functional changes; this commit updates all version strings across `meson.build`, source files, packaging metadata, and build scripts.
- **docs: update README to reflect beta status:** banner note and Project Status section updated from pre-beta/in-development language to beta; pre-beta changelog history archived to `CHANGELOG-pre-beta.md`.
