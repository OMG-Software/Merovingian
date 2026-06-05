## 0.5.6 (in progress — codex/fix-e2ee-bootstrap-key-query)

- `/sync` now reports `device_one_time_keys_count.signed_curve25519 = 0` for a
  fresh logged-in device with no uploaded one-time keys, so Matrix clients get
  an explicit bootstrap signal instead of an empty count object.
- Strict conformance coverage now includes the fresh-device zero-count case for
  `/sync` and a client-shaped local `PUT /sendToDevice/m.room.encrypted/{txnId}`
  scenario that proves nested Olm ciphertext survives into `/sync`
  `to_device.events`.

## 0.5.5 (in progress — codex/fix-messages-eventid-and-preflight-rate-limit)

- Local room creation now persists invite metadata for same-server invitees, so
  `/sync` can populate `rooms.invite.*.invite_state.events` for Element/Cinny
  instead of surfacing an empty invite shell.
- `POST /_matrix/client/v3/rooms/{roomId}/leave` now handles both joined-room
  leaves and invite rejection. The local path persists a fresh
  `m.room.member` leave state event where room state is available, updates the
  durable membership row to `leave`, and wakes `/sync`.
- Invite metadata is deleted when membership transitions to `join`, `leave`, or
  `ban`, including local join/leave flows and inbound federated membership
  updates, so stale invite rows no longer outlive the accepted or rejected
  invite.
- The client-server conformance suite now has strict behavioral scenarios for
  the remaining membership operations: `POST /rooms/{roomId}/invite`,
  `/ban`, `/kick`, `/unban`, `/forget`, and `POST /knock/{roomIdOrAlias}`.
  These no longer treat `404 M_UNRECOGNIZED` as an acceptable placeholder and
  instead assert the state transitions and `/sync` surfaces required by Matrix
  v1.18.
- The local client-server routes now implement those remaining membership
  endpoints, including durable state-event persistence for `invite`, `ban`,
  `kick`, `unban`, and `knock`, `rooms.knock` publication from `/sync`, and
  membership-row deletion for `forget` after the caller has left or been
  banned.
- Encrypted invite-join bootstrap is now covered by real regressions instead of
  room-membership-only assertions. The suite now checks that a newly joined
  encrypted room publishes `device_lists.changed` for room sharers, that the
  first joined-room `/sync` includes bootstrap state such as
  `m.room.encryption`, and that `GET /rooms/{roomId}/messages` no longer
  returns an always-empty `state` array.
- The runtime now records device-list change rows when room sharing starts or
  ends, and `/sync` now emits a full current-state snapshot when a room first
  becomes joined for a user. This closes the gap where membership looked
  correct but Element/Cinny still could not exchange room keys or configure
  encryption after accepting an invite.
- The E2EE conformance suite now covers the full local encrypted invite-accept
  bootstrap path: `keys/changes` notifying room sharers, `keys/query` and
  `keys/claim` returning the recipient's device material, `sendToDevice`
  reaching only the addressed local device, `to_device.events` draining once,
  and the `device_lists.left` edge case where another shared room still exists.
- `GET /_matrix/client/v3/rooms/{roomId}/messages` now serializes timeline
  events through the client event formatter instead of echoing raw stored event
  JSON. That restores required `event_id` fields in `chunk`, which real Matrix
  clients need to parse and decrypt encrypted room history correctly.
- Browser `OPTIONS` preflights now bypass client-server rate limiting. The
  runtime handles preflight before bucket accounting, so repeated cross-origin
  checks no longer consume the actual route quota or trip `429
  M_LIMIT_EXCEEDED` on the subsequent login, `/messages`, or media-config
  request.
- New strict regressions now pin both failures directly: a v1.18 conformance
  scenario asserts that `/messages` returns `event_id` on every room event in
  both `chunk` and `state`, and a runtime regression proves repeated
  preflights stay `200` and do not consume the target route's rate-limit
  bucket.
- Packaging workflow metadata is now consistent with version `0.5.5` across the
  Debian, RPM, FreeBSD, and static Linux packaging scripts and the RPM spec, so
  the package validation job no longer trips over stale `0.5.2` references.

## 0.5.4 (merged)

## 0.5.0 (in progress — feature/0.5.0-rate-limit-and-logging-config)

- Wires the wall-clock rate-limit engine, per-module log-level
  overrides, and audit-row routing into production. The PR #190 commit
  added the engine and helpers; this branch makes them reachable from
  `merovingian.conf` and routes the five high-signal failure call
  sites through the audit pipeline.
- New config keys under `client_rate_limits.*` and `log_modules.*` with
  a parser that accepts dotted target prefixes (e.g.
  `client_rate_limits.per_ip./_matrix/client/v3/login=20/60s`).
  Documented in `config/merovingian.conf.example`,
  `docs/configuration.md`, and the new `docs/log-filtering.md`.
- `/_merovingian/admin/audit` now accepts `?category=` and
  `?event_type=` query-string filters. Unknown categories return 400
  with `unknown audit category: <name>`. Implementation in
  `src/homeserver/runtime.cpp` and `src/homeserver/local_http_router.cpp`.
- Five failure call sites now route through
  `observability::log_diagnostic_audit`:
  `rate_limit.exceeded`, `login.rejected`, `access_token.rejected`,
  `request.rejected`, and `registration_policy.denied`. At severity
  `warning` or above the helper appends a row to `audit_log` with
  the same actor / target / reason as the structured log line.
- New BDD tests: `tests/unit/test_config_client_rate_limits.cpp`
  (4 scenarios), `tests/unit/test_config_log_modules.cpp` (3
  scenarios), `tests/unit/test_audit_filter.cpp` (2 scenarios), and a
  new SCENARIO in `tests/integration/test_client_server_flow.cpp` for
  the round-trip audit-filter request.

## 0.4.62 (in progress — fix/otk-signature-claim)

- Server now rejects `one_time_keys` and `fallback_keys` whose signature
  is not made by the device's own ed25519 identity key. The device's
  signing key is resolved from the in-body `device_keys` first, then
  the persisted `device_keys` row. This was the live bug on
  pong.ping.me.uk where matrix-rust-sdk reported `NoSignatureFound` for
  OTK signatures on the stale `MEROVINGIAN` device row and Element Web
  was stuck on `joining` for the room.
- `tests/unit/test_otk_signature_validation.cpp` adds four BDD
  scenarios (reject imposter-signed OTK, accept own-key-signed OTK,
  reject imposter-signed fallback key, accept first-time OTK before
  device_keys is known).
- Version bumped to 0.4.62 across `meson.build`, `src/main.cpp`,
  `src/db_migrate.cpp`, `packaging/freebsd/+MANIFEST`,
  `packaging/rpm/merovingian.spec`, and the `scripts/build-*.sh` packagers.

# Progress tracker

This is the authoritative progress, readiness, and Matrix v1.18 coverage ledger
for The Merovingian. It replaces the older production-readiness,
alpha-readiness, progress, and protocol-coverage notes. Historical numbered
milestone and phase documents are planning notes only; do not use them to decide
whether a capability is ready.

The latest repository code-audit report is tracked in
`docs/security-code-audit-alpha.md`.

The generated Matrix v1.18 Client-Server API reference used to audit endpoint
coverage is tracked in `docs/matrix-v1.18-client-server-api.md`.

No milestone is complete until every listed `TODO` item for that milestone is
closed and the evidence is recorded in CI or release notes.

## Status model

Use these states consistently:

- `not-started`: no project-owned implementation exists.
- `planned`: route, boundary, or work item is identified, but there is no
  behavior.
- `scaffolded`: types, interfaces, routes, or planning code exist, but there is
  no complete behavior.
- `unit-covered`: behavior exists behind unit tests, but is not wired into the
  runtime path.
- `integrated`: behavior is composed with neighbouring modules in integration
  tests.
- `runtime-wired`: behavior is served through the real executable/runtime path.
- `spec-covered`: behavior is checked against Matrix v1.18 fixtures or
  conformance tests.
- `production-gated`: release, security, CI, fuzz, sanitizer, and deployment
  gates pass for the capability.

No capability is production-ready until it reaches `production-gated`.

## Milestone order

### Alpha

Alpha means federation works. The Matrix network is the product; a homeserver
that cannot federate is a single-server preview, not a Matrix homeserver alpha.
Alpha is still a test-user milestone with bugs expected, not a production
deployment milestone.

#### TODO

_None — all Alpha gates are closed. The alpha release itself remains a
separate operator decision once this branch is approved._

#### DONE

- Build and warning policy: Meson C++26 build, warnings-as-errors, hardening
  flags, Linux and FreeBSD CI, local build wrappers, WSL wrapper, and named
  debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles exist.
- Secure configuration: validated defaults, bounded config parser, commented
  operator example config, config-file metadata checks, reload planning, and
  smoke tests exist.
- Runtime listener: `merovingian::homeserver::serve_http` and
  `serve_tls_http` bind configured listeners, accept HTTP/1.1 requests, dispatch
  client traffic through the Matrix JSON adapter, keep the internal federation
  default on loopback port `8009` for reverse-proxy deployments, document
  Apache httpd/nginx proxy examples, and handle shutdown.
- HTTP transport: request-head parsing, request limits, per-endpoint rate-limit
  policies, response serialization, dispatch-mode separation, OpenSSL RAII
  boundary, libcurl-backed outbound HTTPS client, pinned-address DNS through
  `CURLOPT_RESOLVE`, and `MSG_NOSIGNAL` writes exist.
- Authentication and sessions: LibSodium password hashes, CSPRNG access tokens,
  durable token hashes, register/login/logout/whoami/device routes, policy
  checks, durable audit events, and restart-survival coverage exist.
- Registration discovery and validation: username availability,
  registration-token validity discovery, and homeserver-managed email/MSISDN
  `requestToken` validation-session routes are runtime-wired and covered by
  Matrix v1.18 conformance fixtures.
- Local rooms and events: local create/join/send/state/joined_rooms/sync flows
  are runtime-wired with canonical JSON, Matrix content hashes, reference-hash
  event IDs, persisted signing keys, signed runtime event JSON, event DAG rows,
  room-version-aware redaction, v6+ auth rules, v2 state resolution, encrypted
  room policy, decoded Matrix room path components for browser-encoded join,
  send, and state routes, local `publicRooms` directory listing for
  `public_chat` rooms, and restart-survival coverage.
- Room initial state for federation: `create_room` now generates and persists
  the four required Matrix room state events (`m.room.create`, `m.room.member`
  for the creator, `m.room.power_levels`, `m.room.join_rules`) so that
  `send_join` can return a non-empty auth chain. Synapse previously rejected
  remote joins to locally-hosted rooms with "No create event in state"; this is
  now fixed. The room version policy for event composition is derived from the
  stored `m.room.create` event rather than hardcoded to version 12.
- Room version 12 (MSC4291 + MSC4289): `create_room` derives v12 room IDs from
  the `m.room.create` event's reference hash (`!` + hash, with no `:server`
  suffix), omits `room_id` from the create event, and excludes the create event
  from every event's `auth_events`; redaction drops `room_id` from v12 create
  events so the reference hash and signing payload match a conformant peer
  byte-for-byte. The create-event sender and the users in
  `content.additional_creators` hold an effectively infinite power level
  (MSC4289). This fixes the Synapse `send_join` `BadSignatureError` on the create
  event that blocked cross-server joins and messaging. Room versions 10 and 11
  are unchanged. Spec tests cover all three versions for create-event redaction,
  room-ID derivation, `auth_events` exclusion, creator privilege, and the
  room-version policy flags.
- auth_events per-event-type selection (0.4.45): `auth_events_for_room` now
  returns only the spec-required auth events for each event type: `[]` for
  `m.room.create`, `[create*, power_levels, join_rules, sender_member,
  target_member]` for `m.room.member`, and `[create*, power_levels,
  sender_member]` for all other types. Previously every room state event was
  included, causing Synapse to reject non-member events with "unexpected
  auth_event for ('m.room.join_rules', '')", which cascaded into broken
  invite state and join failures. `compose_signed_event` passes the event
  type, state key, and sender so the correct subset is selected. Unit tests
  cover each event type's auth_events.
- createRoom initial_state dedup (0.4.45): `create_room` now scans
  `initial_state` for client-provided `m.room.join_rules`,
  `m.room.history_visibility`, and `m.room.guest_access` before emitting
  preset defaults, skipping any preset that the client already supplied.
  Previously only `m.room.encryption` had a dedup guard, so clients that
  set guest_access/join_rules/history_visibility in `initial_state` would
  produce duplicate state events. Unit tests verify each type appears once
  and the client's values override the preset defaults.
- v12 power_levels creator omission (0.4.44): `create_room` no longer lists the
  creator or any `additional_creators` in `m.room.power_levels` `content.users`
  for room version 12+, because MSC4291 creators hold an implicit infinite power
  level. Synapse (and the v12 auth rules) reject a power_levels event that names
  a creator (`Creator user ... must not appear in content.users`), which
  previously blocked remote users from joining locally-created v12 rooms,
  including DMs. Creators supplied via `power_level_content_override` are stripped
  too. Pre-v12 rooms still list the creator at level 100. Unit tests pin both.
- v12 `additional_creators` combine/dedup (0.4.44): `create_room` now follows the
  spec (MSC4289, Matrix v1.16) for the `trusted_private_chat` preset in room v12+ by
  combining the `creation_content` `additional_creators` with the `invite` array and
  deduplicating (excluding the sender), rather than overwriting with the invite list.
  The field is gated to room versions whose policy sets `privilege_room_creators`;
  pre-v12 rooms emit no `additional_creators` and grant invitees power level 100.
  Unit tests cover v11 (no field, invitee at 100) and v12 (combined + deduplicated).
- Outbound EDU `edu_type` key (0.4.44): federation `/send` transactions now key
  each EDU by `edu_type` (per spec) instead of `type`. Synapse read
  `edu["edu_type"]`, raised `KeyError: 'edu_type'`, and 500'd the entire
  transaction, silently dropping all federated typing/receipt/presence/to-device
  traffic. Both client-server EDU dispatch paths now share a unit-tested
  `federation::build_edu_transaction_body` helper.
- `createRoom` Matrix v1.18 conformance: `POST /_matrix/client/v3/createRoom`
  now emits the spec-ordered initial state chain, derives presets from
  `visibility`, persists `m.room.guest_access`, honours `room_version`,
  `creation_content`, `power_level_content_override`, `initial_state`,
  `room_alias_name`, and `is_direct`, and exposes client room-directory alias
  lookup/registration routes. Outbound federation invites now advertise the
  created room's actual version instead of a hardcoded value.
- Room encryption for private presets: `create_room` now auto-emits
  `m.room.encryption` with the `m.megolm.v1.aes-sha2` algorithm for
  `private_chat` and `trusted_private_chat` presets when the client does not
  include encryption in `initial_state`. This fixes Element reporting
  "Encryption is not set up" in newly created rooms. Unit tests cover the
  auto-emission, public-chat exclusion, and duplicate-suppression cases.
- `PUT /sendToDevice/{eventType}/{txnId}` implemented: parses the `messages`
  object, enqueues a `PersistentToDeviceMessage` per target user/device, and
  returns `{}`. This was a 404 gap that blocked all E2EE session establishment
  (Olm room-key delivery). Conformance tests verify 200 shape and end-to-end
  delivery via /sync `to_device.events`.
- `GET /keys/changes` implemented: extracts the `sync_stream_id` from the
  composite next_batch token via `sync::decode_stream_token`, then returns
  `changed` and `left` arrays from `device_list_changes`. Conformance tests
  verify shape and the round-trip: Bob joins Alice's room, uploads keys, and
  appears in Alice's `changed` array.
- `GET /rooms/{roomId}/state/{eventType}/{stateKey}` implemented inline in
  `client_server.cpp`: looks up `PersistentStateEvent` → `PersistentEvent`,
  parses the full event JSON, and returns the `content` object. Returns 404
  `M_NOT_FOUND` for absent events, 403 `M_FORBIDDEN` for unknown rooms. Two
  former implementation-gap conformance tests are now real passing assertions.
- Conformance tests for createRoom encryption added to
  `test_client_server_conformance.cpp`: `POST /createRoom` with `private_chat`
  or `trusted_private_chat` preset is now verified via
  `GET /state/m.room.encryption/` in the conformance suite. This class of
  regression will be caught by CI before it reaches users.
- E2EE round-trip conformance tests added: `keys/upload` → `keys/query` round-
  trip, `keys/upload` → `keys/claim` OTK consumption, `sendToDevice` → sync
  `to_device` delivery, and `keys/changes` device-list propagation. These cover
  the full Olm session establishment path for local users.
- Federation E2EE proxying implemented: `POST /keys/query` and `POST /keys/claim`
  now proxy remote users to their home servers via
  `/_matrix/federation/v1/user/keys/query` and `/_matrix/federation/v1/user/keys/claim`
  using `perform_sync_outbound_call` (moved from `room_service.cpp` anon namespace
  to the `homeserver::` named namespace and declared in `room_service.hpp`).
  `PUT /sendToDevice` now dispatches `m.direct_to_device` EDUs for remote users
  via `dispatch_edu_to_server`. Inbound `m.direct_to_device` EDU handling and
  all three inbound federation key endpoints were already implemented.
- Federated inbound `m.direct_to_device` parsing hardened (0.4.55): the
  production sink no longer scans the EDU content with raw brace searches.
  Nested encrypted payloads and multi-device target maps are now traversed as
  canonical JSON and enqueued per target device, which restores the missing
  E2EE room-key delivery path that remote clients rely on before backup
  fallback.
- Outbound federated `m.direct_to_device` transaction IDs hardened (0.4.55):
  federation `/send/{txnId}` IDs no longer reuse the restart-sensitive local
  session counter. Remote to-device fanout now uses opaque federation
  transaction IDs that survive process restarts without colliding with earlier
  deliveries, and the client `PUT /sendToDevice/{eventType}/{txnId}` token is
  preserved as the EDU `message_id` for remote idempotency.
- `.clangd` tab indentation fixed — YAML spec prohibits tabs; spaces now used
  throughout so clangd parses the file and the diagnostic suppressions work.
- FreeBSD portability regression: the `createRoom` follow-up review coverage
  now includes its required standard-library header (`<algorithm>`) so
  `std::ranges::find_if` builds cleanly on libc++-based FreeBSD CI instead of
  relying on Linux-only transitive includes.
- Sync foundation: stream tokens, initial sync, incremental event diffing via
  `since`, Matrix-shaped sync responses with event bodies, invite/leave room
  categories, and top-level `presence`, `account_data`, `to_device`,
  `device_lists`, and `device_one_time_keys_count` stubs are implemented.
- E2EE key API foundation: upload/query/claim/cross-signing/signature/backup
  route shapes are runtime-wired with durable server-blind storage,
  one-time-key consumption, fallback-key reuse, backup rows, redaction, audit,
  and SQLite restart coverage.
- Inbound federation foundation: federation-only listener dispatch,
  inbound transaction scaffold, SSRF/TLS policy checks, duplicate handling,
  canonical JSON Ed25519 request verification, JSON PDU signature verification
  for known keys, signed-request integration coverage, inbound
  `GET /_matrix/key/v2/server` key publication, server discovery with
  `.well-known/matrix/server`, DNS SRV, A/AAAA, IPv6 pins, and private-address
  rejection, outbound transaction types, exponential backoff,
  circuit-breaker policy, `OutboundClient`, `perform_outbound_transaction`,
  and per-platform TLS outbound integration coverage exist.
- Federation request-signing interop: the server Ed25519 signing key_id is now
  derived from the first four public-key bytes as lowercase hex
  (`ed25519:a1b2c3d4` form) instead of the legacy `ed25519:auto` sentinel.
  Legacy `ed25519:auto` entries in the persistent store are ignored and a fresh
  keypair with a derived key_id is generated in their place, bypassing stale
  notary-server (e.g. matrix.org) caches that had the old sentinel locked in
  with a far-future `valid_until_ts`. Newly generated keys use `now + 7 days`
  as `valid_until_ts` so peers re-fetch periodically. Every outbound X-Matrix
  header now carries the actual stored key_id rather than a hardcoded string.
  Synchronous outbound membership calls fail closed when the signing key is
  absent; dispatch-worker startup rejects unusable secrets; `OutboundClient`
  preserves raw encoded request targets with `CURLOPT_PATH_AS_IS`; TLS
  integration coverage captures the exact `make_join` request line to guard
  against signature drift. `/_matrix/key/v2/server` now populates
  `old_verify_keys` from all non-active signing keys in the persistent store,
  with `expired_ts` capped at `now` to prevent future-dated entries from
  superseded keys that carried the year-2999 sentinel.
- Architecture doc rewrite (0.4.27): Expanded `docs/architecture.md` from a sparse
  outline to a comprehensive reference covering source tree, runtime model,
  request flow, data types, database layer, federation subsystem, client-server
  API surface, sync subsystem, build system, testing, and security measures.
- Sync `next_batch` off-by-one fix (0.4.27): The `next_batch` token in `/sync`
  responses was constructed from `next_stream_ordering` (a "next available
  slot" counter, always +1 ahead of the last published event) instead of
  `next_stream_ordering - 1U`. This caused federated users who joined a room
  to get stuck in an infinite empty-sync loop: the client's subsequent `since`
  token pointed to a stream ordering that would never be reached, so the
  long-poll check never fired. Every other usage of `next_stream_ordering`
  already applied the `- 1U` correction — only the token construction was
  missing it.
- Sync long-poll decoupled from main request pool (0.4.26): A dedicated
  32-thread `sync_pool` is created alongside the 8-thread main pool. When a
  `/sync` long-poll needs to wait, `serve_stream` hands the plain-HTTP fd to
  `sync_pool` immediately and returns, freeing the main pool thread. All other
  requests (login, join, send, federation) are always serviced without delay.
  Each async wait is capped at 5 s so server shutdown completes promptly.
  `dispatch_local_http_request()` retains its blocking API for test
  compatibility. TLS connections fall back to the previous blocking path.
- Inbound `make_join` room-version negotiation (0.4.26): the
  `membership_template_provider` now reads the actual room version from the
  `m.room.create` state event and validates it against the joining server's
  `?ver=` query params. Incompatible versions return
  `M_INCOMPATIBLE_ROOM_VERSION` (HTTP 400). The `membership_acceptor` populates
  `room_version` in `MembershipAcceptResult`, and `handle_send_membership`
  echoes it in the `send_join` response body instead of hardcoding "12".
- Remote join template validation (0.4.28, updated 0.4.29): outbound remote joins now validate
  `make_join` responses against the Matrix v1.18 handshake requirements before
  signing them. Merovingian rejects a template when `room_id`, `sender`,
  `state_key`, `type`, `content.membership`, or `origin_server_ts`
  do not match the expected shape, instead of silently repairing malformed
  responses. The `origin` field was removed from events in room version 4
  (hash-based event IDs replaced server-name-based IDs), so it is no longer
  required on make_join templates. Inbound `make_join` templates still include
  `origin_server_ts` by default.
- Restricted join auth bridge (0.4.28): event authorization now accepts the
  `join_authorised_via_users_server` path used by restricted rooms when the
  named resident user is joined and has sufficient invite power. Full
  resident-side evaluation of restricted-room allow conditions remains a
  follow-up item.
- Inbound PDU signing payload fix (0.4.26): `make_event_signing_payload` now
  strips `event_id` from the verification payload when the room version uses
  reference-hash event IDs (all room versions 4+, i.e. every version we
  support). Synapse includes `event_id` in outbound PDUs as a receiver hint,
  but its signing payload never contained the field. This caused
  `crypto_sign_verify_detached` to fail for every inbound encrypted-message
  PDU, making Merovingian return 403 and triggering Synapse's 600-second
  backoff on the federation link.
- Room v12 (MSC4291 + MSC4289) (0.4.39): room ID is now `!` + reference
  hash of the create event (no `:server` domain), create event redaction drops
  `room_id` in v12, create event excluded from `auth_events`, room creators
  hold infinite power (MSC4289). Fixes Synapse `BadSignatureError` during
  `send_join`.
- Accept v12 room IDs in `matrix_id_is_valid` (0.4.40): the validator
  required a `:` in all Matrix IDs, but MSC4291 room IDs are `!` + base64
  hash without a server suffix, causing `send_join` to fail with 400 Bad
  Request ("invalid room_id").
- Federation signing conformance tests (0.4.38): spec-vectored unit tests
  lock in the exact canonical JSON that each room version's signing payload
  must produce. Covers v10 legacy redaction (keeps `origin`), v11+ updated
  redaction (drops `origin`, keeps `invite` in power_levels, keeps all
  `m.room.create` content), content hash base64 alphabet (RFC 4648 standard,
  not URL-safe), event ID base64 alphabet (URL-safe), canonical JSON spec
  vectors (key sorting, Unicode normalisation, `-0`→`0`, integer-only
  representation), and event signing spec vectors (payload construction for
  v1-v2 and v11+ formats). These tests catch regressions that would cause
  `BadSignatureError` on federation peers.
- Remote join content hash (0.4.25): the `make_join` → `send_join` remote
  join path now computes and attaches `hashes.sha256` before signing the join
  event, fixing Synapse rejection with "Malformed 'hashes': `<class
  'NoneType'>`".
- Key server lock-free fast path: `/_matrix/key/v2/server` is now served
  without acquiring the runtime mutex. The signed response is
  pre-computed during `start_runtime` and cached in an atomic
  `shared_ptr<string>` field (`LocalDatabase::key_server_cache`). Subsequent
  requests load the cached pointer atomically and return immediately, ensuring
  Synapse's `ServerKeyFetcher` receives the response well within its
  cancellation window even when a concurrent `make_join` or other long-running
  outbound call holds the mutex for tens of seconds.
- Runtime-scoped request locking: the listener-owned `runtime_lock` has been
  removed. Request synchronization now lives in `HomeserverRuntime::mutex`,
  `SyncNotifier` is attached during `start_client_server`, and the remote join
  path snapshots signing material, releases the mutex for discovery,
  `make_join`, and `send_join`, then reacquires it only for persistence. This
  stops unrelated client requests from serializing behind outbound federation
  I/O. `HomeserverRuntime` now carries explicit move operations so the runtime
  remains movable after introducing the mutex, keeping `start_client_server()`
  and the build matrix green.
- Homeserver public headers: the old `vertical_slice.hpp` umbrella has been
  retired in favor of implementation-matched headers for runtime, auth, room,
  media, local HTTP routing, and the local smoke-flow helper. The split removes
  accidental transitive declarations and makes include intent explicit.
- Media repository foundation: authenticated local upload/download, MIME
  policy, quarantine/release/remove, LibSodium digest, metrics, audit,
  metadata/blob persistence, sandbox/AV/decoder/decompression processing
  boundary, remote-ingest boundary, thumbnail metadata, and integration
  coverage exist.
- Database persistence: prepared-statement boundary, schema inventory,
  migration model, in-memory persistent store, SQLite RAII backend,
  current-schema bootstrap, fail-closed hydration, busy timeout, runtime
  hydration, write-through users/devices/tokens/rooms/events/E2EE
  keys/media/audit/admin rows, SQLite rollback coverage, PostgreSQL RAII
  connection/result boundary, PostgreSQL schema bootstrap/pending-migration
  hydration/write-through path, migration file loading, offline migrator
  scaffold, database role separation, durable trust-and-safety rows, policy
  rules, account data, federation queues, media blob rows,
  restart-survival integration coverage, and base64-safe Ed25519 signing key
  secret storage (prevents null-byte truncation on SQLite/PostgreSQL reload) exist.
- Observability and audit: structured logging, redaction-aware debug
  diagnostics across HTTP dispatch, client-server auth/routing, room joins,
  room events, event authorization, persistence, federation decision paths,
  outbound HTTP request outcomes, media upload/fetch/decoder policy decisions,
  federation dispatch-worker retry/circuit-breaker/delivery events,
  federation security verification rejections, platform hardening self-check
  results, and runtime startup milestones.  Operator-facing `--debug` and
  `--log-file <path>` startup controls, health snapshots, safe metrics
  summaries, redaction helpers, durable audit events, admin
  health/metrics/audit runtime endpoints, and client-server audit persistence
  exist.  Federation signing-pipeline diagnostics (`signature.signing` with
  embedded public key, `signature.key_size_invalid`, `signature.payload_build_failed`)
  and signing-key lifecycle events (`signing_key.loaded`, `signing_key.generating`,
  `signing_key.generated`) surface key-mismatch and regeneration faults at
  runtime without requiring a server restart.  `transaction.failed` log events
  now capture the remote peer's response body for federation error diagnosis.
- Trust and safety: registration/account/invite/federation/media/report policy
  engine, runtime client event reporting, admin safety report listing/review,
  durable policy audit rows, and durable admin action rows exist.
- Packaging scaffolds: systemd, OpenRC, BSD rc.d, Docker assets, Debian control
  metadata, RPM spec metadata, and BSD package metadata exist for early
  deployment-shape testing.
- Distribution packaging: installable `.deb` (Debian/Ubuntu), `.rpm` (Fedora),
  and `.pkg` (FreeBSD) packages are produced by CI on every push. All three
  packages include a sample config file. Security libraries (OpenSSL, libsodium,
  libpq) link dynamically from OS packages so distro security updates (`apt
  upgrade`, `dnf upgrade`) patch them without rebuilding Merovingian; the `.deb`
  declares `libssl3`, `libsodium23`, and `libpq5` as runtime `Depends`.
  Application dependencies (libcurl, SQLite, yyjson) remain statically linked via
  source-pinned Meson wraps. CI also builds an Alpine/musl static Linux fallback
  tarball with `-static-pie` for older distributions that cannot easily consume
  the distro packages. Pushes to `main` replace the rolling GitHub `latest`
  prerelease through repo-scoped `gh release` commands so the artifact
  publication job does not retain stale release state.
- Test isolation: `registration_token_file()` now generates a process-unique
  filename (random salt + atomic counter) so parallel `meson test` jobs do not
  truncate each other's token file mid-write, eliminating intermittent 403
  failures in the rate-limit cross-user isolation test.
- Spec-test guardrails: conformance and spec-facing test files now pin the
  relevant Matrix v1.18 sections in comments and explicitly tell future
  maintainers and LLMs to fix the implementation rather than weakening the
  assertion when a protocol conformance test fails.
- Supply-chain automation: release publication, secret scanning, dependency
  vulnerability triage, and SBOM workflows exist and are checked by the
  release-readiness gate.
- Direct runtime dependencies resolve through committed source-pinned Meson
  wraps for libcurl, SQLite, Catch2, and yyjson. OpenSSL, LibSodium, and
  PostgreSQL libpq resolve from operating-system packages and explicitly
  disallow Meson fallback resolution so distro security updates apply to
  production builds. curl uses the `unstable-external_project` module to build
  from an upstream tarball via its native configure script. The shared make
  shim forwards Meson's staged `DESTDIR` as a make command-line variable so
  upstream Makefiles that assign `DESTDIR=` internally still install into the
  build-local external-project dist directory. The curl packagefile exposes
  curl's installed include root so `<curl/curl.h>` resolves on BSD. The curl
  fallback disables optional zlib and zstd support so its static archive does
  not need undeclared compression libraries at link time. The curl packagefile
  also passes `--disable-dependency-tracking` so automake's `depcomp` bootstrap
  does not fail on NTFS-backed filesystems (WSL builds under `/mnt/c/`). A
  dedicated `scripts/build-wsl.sh` wrapper defaults to `build-wsl`, detects
  stale curl subproject directories (including extracted source trees whose
  copied `meson.build` no longer matches
  `subprojects/packagefiles/curl/meson.build`, and build trees configured
  without `--disable-dependency-tracking`), wipes them automatically, and
  still re-extracts stale curl sources after `--clean` removes the build
  directory for a full rebuild. The wrapper also stages an executable
  Linux-filesystem `make` shim before Meson setup so `external_project`
  invocations do not fail on DrvFS execute-bit handling or CRLF shebangs. The
  Windows `build-wsl.cmd` and `scripts/build-wsl.ps1` launchers now delegate to
  that same wrapper so WSL builds keep the NTFS guardrails even when started
  from Windows. Catch2 fallback builds
  disable Catch2's own upstream SelfTest target; SQLite fallback builds are
  static so sanitizer jobs link sanitizer runtimes through Merovingian's test
  executables. Meson tests run with a default fallback-runtime setup that
  exposes staged curl external-project library directories through
  `LD_LIBRARY_PATH`, and the aggregate Catch2 unit-test binary has an explicit
  CI-sized timeout so fallback, coverage, and sanitizer jobs do not kill a
  passing suite at Meson's 30 second default. Post-build validation scripts that
  execute `merovingian-server` directly also expose those staged curl library
  directories before running dry-run checks. `_FORTIFY_SOURCE=3` is requested
  only for optimized builds so Fedora debug CI does not fail warnings-as-errors
  on glibc's optimization diagnostic. Fedora container CI now covers the Red Hat
  package family in addition to Ubuntu and FreeBSD. Current pinned wrap
  versions: curl 8.20.0, Catch2 v3.14.0, SQLite 3.53.1, yyjson 0.12.0.
- Client discovery: unauthenticated `GET /_matrix/client/versions` returns
  supported versions `v1.1` through `v1.18` with an empty `unstable_features`
  object.
- Response JSON: client-server responses use `canonicaljson::Value` and
  `serialize_canonical` instead of hand-rolled JSON string construction.
- Remote signing key cache: outbound `GET /_matrix/key/v2/server` fetch
  through the pinned `http::OutboundClient`, self-signature verification with
  libsodium for every listed verify key, persistence into
  `server_signing_keys` with `valid_until_ts`, refresh-on-rotation with a
  real wall-clock fallback, and an injectable
  `FederationRuntimeState::remote_key_resolver` that returns discovery-seeded
  remote runtime records for inbound request and PDU signature verification.
- Outbound dispatch worker: bounded queue with per-destination retry
  state, configurable max-retries/backoff, deterministic clock and
  resolver injectables, and a request_shutdown / drain / join lifecycle
  driving `perform_outbound_transaction`, honoring
  `destination_should_retry`, and requeueing circuit-open transactions for
  the destination retry deadline. Pending outbound transactions and destination
  retry state are persisted to `federation_transactions` and
  `federation_destinations`, then replayed into a restarted worker; shutdown
  leaves backoff-delayed rows durable for the next start. All
  `PersistentStore` mutations from the worker are serialised under the worker
  mutex, durable persistence failures on the retry/delivery paths are treated
  as hard failures rather than silent drops, and replay parks rows beyond
  `max_queue_depth` in an overflow buffer that drains into the active queue
  as in-flight work completes.
- Inbound PDU + EDU ingestion: canonical-JSON transaction body parser,
  PDU envelope extraction, `FederationRuntimeState::pdu_sink` and
  `edu_sink` hooks, classification and per-type content validation for
  `m.typing`, `m.receipt`, `m.presence`, `m.direct_to_device`, and
  `m.device_list_update`. PDU state conflicts now flow through a
  state-resolution v2 merge via `apply_state_resolution_v2` and a wired
  `state_conflict_resolver`; merged forks count as appended and audit as
  `federation.pdu_state_resolved`, while resolution failures retain the
  original `federation.pdu_state_conflict` audit.
- Federation membership and history endpoints: inbound `make_join`,
  `make_leave`, `make_knock`, `send_join` (v1 + v2), `send_leave`
  (v1 + v2), `send_knock`, `invite` (v1 + v2), and `backfill` are
  dispatched through typed runtime hooks
  (`membership_template_provider`, `membership_acceptor`,
  `invite_handler`, `backfill_provider`). Unwired endpoints respond
  `501 Not Implemented`. Outbound counterparts
  (`make_outbound_make_membership`, `make_outbound_send_membership`,
  `make_outbound_invite`, `make_outbound_backfill`) compose
  `OutboundTransaction` records carrying the spec-defined targets,
  query parameters, and v1/v2 invite body shapes.
- Fix (0.4.36): `/sync` timeline events previously returned only `event_id`
  and `sender`; they now include the full signed event content (`type`,
  `content`, `sender`, `event_id`, `origin_server_ts`, `state_key`) so clients
  can render messages and derive room version from `m.room.create`. The `state`
  section previously returned `{"member_count": N}` instead of actual state
  events; initial sync now includes the complete current room state. The
  `room_version_for_room` fallback was changed from `"10"` to `"12"` to match
  the `createRoom` and capabilities endpoint defaults. These fixes resolve
  Element reporting "room version 1, marked as unstable" on newly created rooms.
- Sync v1.18 conformance: `GET /_matrix/client/v3/sync` now populates
  every documented top-level key. `presence.events`,
  `account_data.events` (global and per joined room),
  `to_device.events`, `device_lists.changed` / `.left`,
  `device_one_time_keys_count`, and `device_unused_fallback_key_types`
  read from the persistent store. Long polling blocks on a
  `SyncNotifier` until a sync-relevant `next_sync_stream_id` advance.
  The `filter` query parameter accepts inline JSON filters covering
  room include/exclude lists, timeline limit/sender/type predicates,
  and `include_leave`. Schema v7 (`sync_surfaces_tables`) adds the
  backing rows. `StreamToken` carries a third `sync_stream_id`
  segment so `next_batch` covers all surfaces. A Complement-style
  JSON fixture (`tests/fixtures/complement/sync_v1_18.json`) drives
  the spec shape end-to-end.
- Live PostgreSQL integration coverage with runtime/migration role
  enforcement: a dedicated GitHub Actions workflow
  (`.github/workflows/postgres-integration.yml`) starts a PostgreSQL 16
  service, provisions `merovingian_migration` (DDL) and
  `merovingian_runtime` (DML-only) roles via default privileges, and
  runs live integration scenarios that assert schema bootstrap reaches
  `current_schema_version`, persisted rows survive a close/reopen, and
  a runtime-role session is denied `CREATE TABLE`. The
  `PostgresqlConnection` API exposes `set_postgresql_role`,
  `reset_postgresql_role`, and `current_postgresql_user` so runtime
  callers can switch identities within a single connection; role names
  are validated against PostgreSQL identifier shape before being
  interpolated.
- Fuzz targets run in CI for canonical JSON and HTTP transport. A
  dedicated GitHub Actions workflow (`.github/workflows/fuzz.yml`)
  builds the harnesses with `-fsanitize=fuzzer,address,undefined` and
  runs each target for a bounded duration (120s per push, 900s on the
  Sunday scheduled run). `tests/fuzz/meson.build` enforces the
  libFuzzer flag set, and `scripts/run-fuzz-targets.sh` makes the same
  gate runnable locally. Findings, crash inputs, and corpora are
  uploaded as workflow artifacts.
- Fail-closed alpha hardening controls. `HardeningStatus::alpha_exception`
  and a `note` field replace the prior `unknown` placeholders in
  `run_startup_hardening_self_check`. `HardeningSelfCheck` exposes
  `production_blockers()`, `production_blocker_count()`,
  `is_production_ready()`, and `is_alpha_ready()`. `merovingian-server`
  refuses to start when any check reports `disabled`, logs
  alpha-exception checks at warning level with a documented note, and
  prints a `production_ready=…/alpha_ready=…` readiness summary. The
  deferred controls and their beta/production retirement plans are
  documented in `docs/hardening-alpha-exceptions.md`, which the
  release-readiness script requires.

### Beta

Beta means the homeserver has broad Matrix v1.18 behavior coverage, can survive
realistic operator testing, and can federate with selected remote homeservers in
a non-production environment.

#### TODO

- Promote remaining endpoint behavior from `partial` to `spec-covered` with
  conformance fixtures.
- Add live PostgreSQL integration tests that cover transaction rollback,
  migration ordering, and role-grant failures.
- Wire live media remote-fetch transport and server discovery into the
  repository remote-ingest boundary, then replace thumbnail metadata with real
  image resampling output.
- Define the production scrape/export contract, log format contract, trace
  correlation, and operator docs for observability.
- Add policy server transport integration, durable policy-rule management, and
  richer moderation workflows.
- Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and
  documented support tiers.
- Add corpus management, broader fuzz execution, property tests, load tests,
  and chaos tests.

#### DONE

- Login `device_id` collision fix (0.4.61).
  `POST /_matrix/client/v3/login` no longer defaults `device_id` to
  the literal string `"MEROVINGIAN"` when the client omits it.
  Matrix v1.18 §5.3.2 requires the server to mint a unique opaque
  id in that case; the literal caused every device-id-less login to
  collide on a single shared device row, so two users (or two
  device-id-less devices of the same user) shared one `device_keys`
  upload slot and E2EE key bundles pointed at the wrong identity
  key. The server now generates a fresh 128-bit hex `device_id` per
  login when the body does not include one, and the new "Login
  without device_id generates a unique opaque id" BDD scenario
  guards the fix.
- E2EE key bundle bootstrap (0.4.61). `keys/upload` persists the
  device's `device_keys` / `one_time_keys` / `fallback_keys` to the
  persistent store, and `keys/query` returns them to other users in
  shared rooms with uploaded signatures merged back into the
  response. Element's "No key bundle found for user" log clears as
  soon as the inviter completes its first `keys/upload` round-trip.
- CORS self-sufficient preflight (0.4.60). Merovingian now emits
  `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`,
  `Access-Control-Allow-Headers`, `Access-Control-Max-Age`, and
  `Vary: Origin` on every response, so a vanilla reverse proxy that
  does not synthesize CORS headers stops breaking browser clients
  on every cross-origin request. New `server.cors.*` config keys
  (`allowed_origins`, `max_age`, `allow_credentials`, `allow_methods`,
  `allow_headers`) cover the policy surface; wildcard `*` is the
  default and is safe for Matrix because clients use bearer tokens.
  `docs/configuration.md` reverse-proxy examples rewritten for
  nginx, Apache, Caddy, Traefik, HAProxy, and Cloudflare.
- Audit follow-up sweep (0.4.59). Canonical-JSON integer parsing now rejects
  leading zeros and explicit `+`; yyjson adapter passes
  `YYJSON_READ_STOP_WHEN_DONE` to reject trailing-garbage payloads; HTTP
  `read_request_head` gains a 30 s overall deadline plus a 5 s inter-byte cap
  to defeat slowloris; thread-pool and http-server swallowed-exception sites
  log the demangled type and `what()`; `schema_migrations` INSERT switched to
  a `PreparedStatement`; `request_stop` and `sqlite_transient_destructor`
  non-reentrancy / lifetime contracts are now documented and debug-asserted.
- Alpha foundations listed above.
- Federation request signing and PDU signature verification boundaries exist for
  known keys.
- PostgreSQL schema bootstrap, hydration, write-through path, and database role
  separation scaffolding exist.
- Admin health, metrics, audit, media moderation, and trust-and-safety review
  routes exist.
- Matrix UI-Interactive Authentication for `POST /register`: absent `auth` field
  returns 401 with `m.login.registration_token` flow, `params`, and `session`.
  Incomplete auth (missing `token` for `m.login.registration_token` or wrong
  `auth.type`) also returns 401 with the UIA challenge — not 403.
- `POST /account/password` for authenticated password change with Argon2id
  hashing and persistent-store write-through.
- `PUT /profile/{userId}/displayname` and `PUT /profile/{userId}/avatar_url`
  with cross-user 403 protection.
- `GET /profile/{userId}` moved before the auth gate (unauthenticated per spec).
- Client-server v1.18 conformance fixture extended with profile negative cases,
  unknown-room state 403, and password-change coverage.
- Redaction-aware debug diagnostics are wired into room join, auth, HTTP,
  persistence, and federation paths, exposed through `--debug` and
  `--log-file <path>`, with operator notes in
  `docs/debug-logging.md`.
- X-Matrix Authorization header parsing: `parse_x_matrix_authorization_header`
  extracts `origin`, `destination`, `key_id`, and `sig` from inbound federation
  Authorization headers. TLS-bound origin validation rejects requests where
  `tls_peer_server_name` differs from `origin` with a 403 before any further
  processing. Unit coverage exists for valid, minimal, missing-field, malformed,
  and wrong-scheme inputs plus TLS match, empty, mismatch, and prefix cases.
- Federation runtime callbacks wired: `pdu_sink`, `state_conflict_resolver`,
  `membership_template_provider`, `membership_acceptor`, `invite_handler`,
  `backfill_provider`, and `remote_key_resolver` are lazily wired into
  `FederationRuntimeState` on the first inbound federation request.
  `pdu_sink` persists inbound PDUs through the persistent store.
  `state_conflict_resolver` runs state-resolution v2 via
  `apply_state_resolution_v2`. Membership hooks cover `make_join`,
  `make_leave`, `make_knock`, `send_join`, `send_leave`, `send_knock`, `invite`,
  and `backfill` from durable event rows. `remote_key_resolver` uses
  `make_persistent_remote_key_resolver` with a real wall-clock for discovered
  and rotation-triggered remote key fetch and cache. BDD coverage for all
  callbacks exists in `test_federation_runtime_callbacks.cpp`.
- PostgreSQL restart-survival coverage extended: integration tests assert that
  users, access tokens, rooms, memberships, events, account data, policy rules,
  federation destinations, federation transactions, local media, and remote media
  all survive a close/reopen cycle on a real PostgreSQL-backed persistent store.
- Bug fix (0.4.1): `POST /join/{roomIdOrAlias}` no longer returns 500 when the
  user is already a member in the persistent store but absent from the in-memory
  `LocalRoom::members` list. `store_membership` now returns a tri-state
  `MembershipStoreResult` (`stored`, `already_exists`, `error`); the room
  service treats `already_exists` as an idempotent success and re-syncs the
  in-memory member list. Regression test added to the vertical-slice suite.
- Bug fix (0.4.2): Federation invite path parsing (`v1`/`v2` invite routes)
  no longer emits a spurious `membership_path.rejected` diagnostic. The invite
  endpoint is now handled natively by `parse_membership_path` instead of
  falling through to a `send_join` hack with manual fallback parsing.
- Feature (0.4.2): Added `im.nheko.summary` room summary endpoints for Nheko
  compatibility. Both `GET /summary/{roomId}` and `GET /rooms/{roomId}/summary`
  paths return room membership summaries instead of 404.
- Bug fix (0.4.3): Inbound federation PDU events now receive `stream_ordering`
  and trigger sync notification, so remote messages appear in `/sync` responses.
- Feature (0.4.3): Outbound PDU dispatch wired from `send_event` to the
  `DispatchWorker`. Local events sent to rooms with remote members are now
  forwarded to remote servers via federation `PUT /_matrix/federation/v1/send`.
- Feature (0.4.4): Inbound EDU sink wired for all five EDU types (typing,
  receipt, presence, direct_to_device, device_list_update). Remote EDUs are
  classified, validated, and dispatched to the appropriate runtime handler.
- Feature (0.4.4): Outbound membership wired into `join_room` for remote rooms.
  Local users joining a room not in the database now perform a synchronous
  `make_join` → sign → `send_join` flow with the remote homeserver.
- Fix (0.4.46): PDU dispatch now includes invited users in `room->members` so
  federated events are delivered to invitees' home servers. Previously only
  "join" members were added at runtime, causing invitees' servers to never
  receive room events. `apply_runtime_membership` now handles "invite" (add)
  and "ban" (remove) transitions. Runtime startup filters to only "join" and
  "invite" memberships, consistent with runtime behavior.
- Feature (0.4.46): Receipt endpoint `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}`
  per Matrix spec v1.18. Federates `m.receipt` EDUs and updates local receipt state.
- Feature (0.4.46): User directory search `POST /user_directory/search`
  per Matrix spec v1.18. Case-insensitive substring match on displayname and user_id.
- Feature (0.4.46): Media thumbnail `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}`
  and `GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` per spec v1.18.
- Fix (0.4.52): Data race in `OutboundClient` (federation outbound HTTP). The
  client reused one libcurl easy handle per instance, but the runtime shares a
  single instance across the dispatch-worker thread and the HTTP request-handler
  thread pool. Concurrent `perform()` calls (e.g. a client `/keys/query`
  federation proxy overlapping a dispatch-worker transaction to the same peer)
  corrupted the handle and returned a spurious `network_error` in 0 ms; the
  empty remote `device_keys` result then caused the client to emit
  `m.room_key.withheld`, breaking E2EE. `perform()` now drives a per-thread easy
  handle (lazily created, freed at thread exit), so one instance is safe to
  share across threads. `OutboundClient` is now stateless. Added a BDD
  concurrency regression test in `tests/unit/test_outbound_client.cpp`.
- Infra (0.4.52): Added a ThreadSanitizer `tsan` job to
  `.github/workflows/sanitizers.yml` (`-Db_sanitize=thread`) with a
  dependency-scoped suppressions file at `tests/sanitizer/tsan.supp`. The prior
  sanitizer job ran only ASan+UBSan, which cannot detect data races — the reason
  the `OutboundClient` race went uncaught. Documented the concurrency-testing
  expectation in `docs/testing-standards.md`.
- Test (0.4.52): Added a workflow tooling guard in
  `tests/tooling/test_security_workflows.py` that asserts the sanitizer matrix
  keeps both the `asan-ubsan` and `tsan` jobs, and that the TSan job points at
  `tests/sanitizer/tsan.supp`. This prevents the new race-detection coverage
  from being removed silently by a later workflow edit.
- Fix (0.4.52): The unified `build.py` WSL target now exposes the same
  profile/sanitizer controls as the Linux and BSD targets and forwards them to
  `scripts/build-wsl.sh`. The WSL wrapper now parses `--profile`,
  `--buildtype`, `--sanitize`, `--coverage`, `--build-fuzz`, and
  `--hardening`, maps the named profiles to the same Meson settings as
  `build-linux.sh`, and therefore supports direct `asan`/`ubsan` and `tsan`
  execution through `python build.py wsl`. Tooling tests pin both the Python
  forwarding and the shell-wrapper option handling, and the developer docs now
  show the supported WSL sanitizer invocations.
- Fix (0.4.53): Room-key backup session lookup now percent-decodes Matrix path
  components before matching stored backup rows. Real Megolm session IDs can
  contain `/`, so clients call
  `GET /room_keys/keys/{roomId}/{sessionId}?version=1` with `%2F` in the
  `sessionId` path component after uploading the backup via batch `PUT
  /room_keys/keys?version=1`. Merovingian previously looked up the still-encoded
  path fragment against the decoded session ID stored from the JSON body,
  returning 404 `M_NOT_FOUND` immediately after a successful upload. The
  room-key backup path parser now decodes `room_id` and `session_id`
  consistently for direct PUTs and GETs, and a v1.18 conformance regression
  series now pins the batch-upload -> encoded room-level GET, batch-upload ->
  encoded session-level GET, and direct encoded PUT -> GET round-trips.
- Fix (0.4.54): Matrix v1.18 room-key backup metadata and update responses now
  include the required `count` and `etag` fields. `GET /room_keys/version` and
  `GET /room_keys/version/{version}` now return backup metadata with session
  count and opaque etag, while batch and direct room-key backup writes/deletes
  return `RoomKeysUpdateResponse` instead of placeholder `{"version":"1"}`
  bodies. The backup etag is derived from the stored session set so it changes
  when an existing backup entry is overwritten without changing the total key
  count. `DELETE /room_keys/keys/{roomId}/{sessionId}` now actually removes the
  stored session instead of returning a no-op 200 response.
- Fix (0.4.55): Matrix v1.18 one-time-key claim fallback semantics now hold for
  both client-server and federation key claims. `POST /keys/claim` and
  `POST /_matrix/federation/v1/user/keys/claim` now return a matching fallback
  key when one-time keys are exhausted, instead of incorrectly returning no
  key. This restores the spec-required fallback path for Olm session
  establishment once uploaded OTKs have been consumed.
- Fix (0.4.55): fallback-key lookup now filters by the requested algorithm.
  Merovingian previously stopped on the first fallback key stored for a device,
  so mixed fallback uploads such as `curve25519:*` plus
  `signed_curve25519:*` could cause a `signed_curve25519` claim to miss an
  otherwise valid key. Added regression coverage for both client-server and
  federation claim paths.
- Fix (0.4.55): uploaded signatures now flow back through `POST /keys/query`
  per Matrix v1.18. `POST /_matrix/client/v3/keys/signatures/upload` was
  storing signatures under the wrong target key identifier, so later key
  queries omitted the uploaded signature objects for both device keys and
  cross-signing keys.
- Fix (0.4.55): room-level key-backup routes now follow Matrix v1.18.
  `PUT /_matrix/client/v3/room_keys/keys/{roomId}` persists each session under
  the targeted room, `DELETE /_matrix/client/v3/room_keys/keys/{roomId}`
  removes only that room's sessions, and `GET /_matrix/client/v3/room_keys/keys/{roomId}`
  stays routed with encoded Matrix path components and `?version=...`.
- Add (0.4.55): v1.18 conformance fixtures for signed federation E2EE key
  routes and key publication: `POST /_matrix/federation/v1/user/keys/query`,
  `POST /_matrix/federation/v1/user/keys/claim`,
  `GET /_matrix/federation/v1/user/devices/{userId}`, and
  `GET /_matrix/key/v2/server`.
- Fix (0.4.55): federated `GET /_matrix/federation/v1/query/profile` now
  answers existing local users even when the `profiles` table has no row for
  them yet. The runtime falls back to the durable user record and returns an
  empty `displayname` / `avatar_url` object instead of treating the known user
  as absent.
- Fix (0.4.51): `m.receipt` federation EDU content format — the receipt content
  was built as `{roomId:{userId:{event_ids,ts}}}` but the spec requires
  `{roomId:{receiptType:{userId:{event_ids,data:{ts}}}}}`. The missing
  receipt-type nesting and `ts` outside `data` caused Synapse to 500 every
  outbound transaction containing a receipt EDU, opening the circuit breaker and
  blocking all subsequent federation (including E2EE to-device key exchange).
  Extracted `build_receipt_edu_content` pure helper; used by both `/receipt/`
  and `/read_markers` endpoints.
- Fix (0.4.50): Key backup routing — `PUT /room_keys/keys?version=N` returned 404
  because `match_key_api_route` compared path templates against the full target
  including the query string. Fix strips the query portion before exact-match.
  `PUT /room_keys/keys/{roomId}/{sessionId}` was also storing `?version=N` as
  part of the `session_id`; fix strips query string from the path suffix before
  splitting. `GET /room_keys/keys/{roomId}/{sessionId}` was returning a hardcoded
  `{"rooms":{}}` stub; it now looks up the session in `persistent_store` and
  returns 404 M_NOT_FOUND when the session is absent. Room-level GET
  (`/{roomId}` without a session component) retains the existing stub.
- Feature (0.4.46): Key backup batch PUT `PUT /room_keys/keys` per spec v1.18.
  Stores all sessions from request body, returns `{"version":"1"}`.
- Feature (0.4.46): v1 media download endpoint `GET /_matrix/client/v1/media/download/{serverName}/{mediaId}`
  (authenticated variant) per spec v1.18.
- Conformance tests (0.4.46): Enhanced with positive (success) verification for receipt,
  user directory search, key backup batch PUT, media upload, media download (v3/v1),
  and media thumbnail (v3/v1) endpoints. Tests now verify correct response data and
  runtime state, not just that routes return 404 for missing resources.
- Feature (0.4.4): Device list update route wired. `PUT /devices/{deviceId}`
  now records device list changes for all local room-sharers via
  `record_device_list_change` and publishes sync notifications.
- Feature (0.4.4): Outbound EDU dispatch for typing and receipts. Local typing
  and read-marker requests now federate `m.typing` and `m.receipt` EDUs to
  remote servers with members in the room.
- Feature (0.4.4): Presence route wired. `PUT /presence/{userId}/status` now
  persists presence state via `set_presence` and publishes sync notifications.
- Infra (0.4.35): GitHub Actions CI, package, and release workflows now use
  ccache compiler caching (`hendrikmuhs/ccache-action`) to speed up builds.
  Linux, Fedora, Alpine, and Debian container jobs cache compiler output across
  runs. FreeBSD VM jobs are excluded due to VM action limitations.
- Feature (0.4.34): `GET /account/3pid` returns `{"threepids":[]}` and `GET /pushers`
  returns `{"pushers":[]}`, fixing Element account and notification settings pages.
  `GET /rooms/{roomId}/members` now synthesizes a fallback `m.room.member` event
  from the membership record when no persisted state event exists, fixing empty
  member lists for locally-joined users. Outbound federation invite signatures
  now use the pruned (redacted) event form matching Synapse's
  `compute_event_signature` behavior, fixing `BadSignatureError` rejections
  for invite events with extra content fields like `is_direct`.
- Feature (0.4.33): Comprehensive Matrix v1.18 Client-Server API conformance test
  suite added. 221 test scenarios cover all 165 spec operations across session
  management, account management, capabilities, devices, E2E key API, media,
  room creation/directory/discovery/membership/participation, user data, presence,
  push notifications, reporting, VoIP, event relations, search, send-to-device,
  server administration, well-known, spaces, threads, third-party lookup, OpenID,
  user directory, and untagged endpoints. Implemented endpoints verify 200 response
  shapes and required fields; gap endpoints document the current 404 M_UNRECOGNIZED
  response with clear IMPLEMENTATION GAP comments.
- Feature (0.4.5): Client-server v1.18 conformance fixtures extended with login
  edge cases, createRoom with name and visibility, room join and leave, message
  send idempotency, and PUT state events. Seven client-server endpoints promoted
  from `partial` to `spec-covered`.
- Feature (0.4.5): Federation v1.18 conformance fixtures added. BDD scenarios
  cover inbound make_join, send_join, make_leave, send_leave, invite (v1/v2),
  backfill, key publishing routing, and unwired-endpoint 501 hardening.
- Fix (0.4.5): DispatchWorker overwrite in `wire_federation_callbacks_impl` that
  replaced a test-injected dispatch worker with a new one.
- Fix (0.4.5): Empty `transaction_id` in outbound membership and EDU transactions
  causing `transaction_is_well_formed` rejection.
- Fix (0.4.30): Federation join state events from the `send_join` response were
  stored with `stream_ordering == 0`, making them invisible to incremental
  `/sync`. The sync handler filters events where `stream_ordering <= since_ordering`,
  and `0 <= any_since_ordering` is always true. Combined with the incremental
  suppression that omits rooms with empty timeline and account data, the joined
  room was absent from sync. The `join_room` path now assigns proper stream
  ordering from `next_stream_ordering++`, parses `depth`, `prev_event_ids`, and
  `auth_event_ids` from the event JSON, computes hash-based event IDs for room
  v4+, creates `PersistentStateEvent` entries, and calls `store_event_with_state()`.
- Fix (0.4.30): Cross-signing key upload (`POST /keys/device_signing/upload`) only
  stored the `master` key type, discarding `self_signing` and `user_signing` keys.
  The handler now parses the request body and stores each key type individually.
  The `keys/query` response now includes `master_keys`, `self_signing_keys`, and
  `user_signing_keys` sections, fixing Element's "Unable to set up keys" error
  during E2EE cross-signing setup.
- Fix (0.4.29): `validate_make_join_response` rejected make_join event templates
  that omitted the `origin` field. The `origin` field was removed from events in
  room version 4 (hash-based event IDs replaced server-name-based IDs), so
  Synapse and other homeservers sending templates for room versions 10/11/12
  omit it. The field is no longer required.
- Fix (0.4.29): Inbound make_join/make_leave template generation included the
  `origin` field in the event object for room version 4+, which is incorrect per
  the Matrix v1.18 spec. `build_make_template_response` now checks
  `EventIdFormat::reference_hash` and omits `origin` for room versions 4 and
  later. The conformance test that asserted `origin` was present for room version
  12 was corrected to assert its absence.
- Fix (0.4.28): `PUT /_matrix/federation/v1/send/{txnId}` returned HTTP 403 for
  the entire transaction when any single PDU failed signature verification. Per
  the Matrix federation spec, individual PDU failures must be reported inside
  `{"pdus": {"$event_id": {"error": "reason"}}}` at HTTP 200. Returning 4xx
  caused Synapse's `retryutils` to back off the destination for 600 s, blocking
  all subsequent federation including join acknowledgements.
- Fix (0.4.28): Incremental `/sync` with `can_wait=false` (long-poll timeout
  re-dispatch) emitted the full membership state of every joined room on every
  5-second cycle even when nothing had changed since the `since` token. The
  room-join loop now skips rooms where both `timeline_events` and
  `room_account_data` are empty, so `rooms.join` is empty in the response
  rather than returning 476 bytes of stale state on each timeout.
- Fix (0.4.28): Inbound `send_join` (v2) response was missing the `"event"`
  field. Per Matrix federation spec §11.5.1 the resident server must echo the
  accepted join event back in the response body. `MembershipAcceptResult` gains
  `signed_event_json`; `handle_send_membership` serialises it under `"event"`
  for `send_join` only; `send_leave` and `send_knock` are unaffected.
- Fix (0.4.6): `PUT /_matrix/federation/v1/send/{txnId}` response body returned
  plain-text diagnostic strings instead of the Matrix-required `{"pdus":{}}` JSON,
  causing Synapse JSONDecodeError on transaction responses.
- Fix (0.4.7): `runtime_lock` held during `/sync` long-poll wait blocked
  federation request dispatch for up to 30 seconds, causing Synapse
  CancelledError on profile queries and key claims. Lock is now released
  before the condition_variable wait and reacquired after.
- Fix (0.4.7): `SyncNotifier` only tracked `sync_stream_id`; timeline events
  from local actions never woke parked `/sync` requests. Extended to track
  both `stream_ordering` and `sync_stream_id` so either counter advancing
  wakes all waiters.
- Fix (0.4.7): Missing `sync_notifier->publish()` calls on room leave,
  client-side typing and read receipts, federation send_join membership
  acceptance, inbound typing and receipt EDUs, device deletion, and device
  key uploads. Each path now publishes with the correct stream counters so
  `/sync` long-polls return promptly.
- Fix (0.4.7): `record_device_list_change` not called on device deletion or
  device key upload; other users sharing a room with the affected user did
  not see the device list change in their `/sync` stream.
- Fix (0.4.7): `stream_ordering=0` in federation `membership_acceptor` caused
  inbound `send_join` events to be silently skipped by the `/sync` timeline
  filter. `next_stream_ordering` is now advanced before storing the event.
- Fix (0.4.7): `next_sync_stream_id` not advanced on membership changes
  (room creation, local join, remote join, leave) made the publish call a
  no-op, so `/sync` timed out instead of waking on membership changes.
- Fix (0.4.8): Single-threaded listener model caused all client-server and
  federation requests to be processed one at a time. Replaced with a bounded
  `ThreadPool` of `std::jthread` workers for concurrent request dispatch.
- Fix (0.4.8): `dispatch_lock` parameter threaded through handler signatures,
  leaking lock management into the handler chain. Replaced with two-phase
  `DispatchResult` dispatch: handlers return `needs_wait` instead of managing
  the lock, and `dispatch_local_http_request()` handles the wait/retry cycle
  transparently.
- Fix (0.4.8): `SocketHandle` fd ownership transferred incorrectly to pool
  workers — `native_handle()` followed by reset closed the fd before the
  worker could read. Added `SocketHandle::release()` to transfer ownership
  without premature close.
- Fix (0.4.16): The server Ed25519 signing key secret is now persisted in
  `server_signing_keys.secret_key` and restored on startup. Previously every
  restart generated a new keypair; the UPSERT overwrote the public key while
  the secret lived in-memory only, so Synapse's cached copy of the old public
  key became invalid and all outbound federation requests were rejected with
  `401 Unauthorized`, opening the circuit breaker after three failures.
- Fix (0.4.13): Inbound federation invites now persist stripped invite-state
  metadata and replay it through `rooms.invite.*.invite_state.events` in
  `/sync`, so Element can render direct-message invites initiated from a
  Synapse homeserver. The durable invite metadata now lives in the initial
  schema shape rather than a follow-on migration step.
- Fix (0.4.13): `README.md` now starts with an explicit active-development /
  not-ready warning, explains Merovingian's security-first design goals, and
  links directly to deployment/runtime and development onboarding docs.
- Fix (0.4.13): Outbound federation membership requests now percent-encode
  Matrix room, user, and event IDs in the signed request target, so Synapse no
  longer rejects remote invites with `401 Unauthorized` because of URI/signature
  mismatches.
- Fix (0.4.11): Server startup now logs `Starting merovingian-server <version>` before
  configuration loading, so operators can identify the running binary version
  from startup logs. Normal help/startup surfaces no longer describe the
  server as a bootstrap server; bootstrap wording is reserved for the explicit
  admin bootstrap path.
- Chore (0.4.12): Bump project, binary, and packaging metadata to `0.4.12` so
  the next merge to `main` emits a fresh `push` event for the rolling `latest`
  package workflow under the repository's pull-request-only branch rules.
- Fix (0.4.11): Low-severity console and file logs now flush every 1 second or
  every 100 messages, whichever comes first, so quiet debug sessions no longer
  wait for a high-severity line or a large backlog before output appears.
- Fix (0.4.11): Matrix event signing now uses the full canonical event payload
  rather than a redacted copy, so Synapse can verify federated room-state
  signatures during joins.
- Fix (0.4.11): Federation `send_join` responses now include `room_version` and
  `origin`, and other `send_*` membership responses include `room_version`,
  matching the documented v1.18 response shape.
- Fix (0.4.11): Federation membership path parsing now percent-decodes encoded
  room and event IDs before invite validation, so Synapse federation invites
  no longer compare decoded event JSON against encoded path segments.
- Fix (0.4.11): Apache httpd and nginx deployment examples now split
  `/_matrix/client/` from `/_matrix/federation/` and `/_matrix/key/` on `443`,
  matching `/.well-known/matrix/server` delegation to the federation listener.
- Fix (0.4.11): Configuration and getting-started guidance now state clearly
  that running Merovingian behind a reverse proxy is the preferred deployment
  model for public TLS and routing.
- Fix (0.4.10): Inbound federation `send_join` accepted the event but did not
  update durable membership or the runtime room member list. Accepted remote
  joins now become real room members so later local messages are dispatched to
  the remote homeserver.
- Fix (0.4.10): Inbound federation invites were echoed without local side
  effects. The invite handler now validates the local target user, signs the
  invite event with the local server key, persists `invite` membership, and
  wakes `/sync` so the invite is visible to the client.
- Fix (0.4.10): `createRoom` ignored remote users in the `invite` array.
  Remote invitees now get a signed membership invite and an outbound federation
  invite transaction with a queue transaction id accepted by `DispatchWorker`.
- Fix (0.4.10): Package helper scripts now build `0.4.10` Debian, RPM,
  FreeBSD, and static Linux artifacts, keeping generated archive names aligned
  with the package metadata.
- Fix (0.4.10): Remote-room joins only added the local user to the runtime
  room. The `send_join` state response now hydrates joined remote members and
  persists the remote room so post-join messages have federation destinations.
- Fix (0.4.31): `POST /room_keys/version` returned an empty JSON object `{}`
  instead of `{"version":"1"}`. Element displayed "Unable to set up keys" and
  could not reference the newly created backup. The handler now injects the
  `version` field into the stored payload before returning.
- Fix (0.4.32): `DELETE /room_keys/version/{version}` fell through to `return
  true` without touching the database. Element polled `GET /room_keys/version`
  immediately after delete; finding the backup still present it retried delete
  indefinitely. A new `delete_key_backup_version` database function removes the
  version from `key_backup_versions` and issues a `DELETE` SQL statement.
  Conformance tests assert 200 on delete and 404 on subsequent GET.
- Feature (0.4.32): `GET /rooms/{roomId}/members` implemented. The endpoint
  was absent, causing Matrix clients to receive 404 when building the member
  list sidebar after room creation. The handler iterates `store.memberships`
  filtered by room ID, resolves each member's `m.room.member` state event from
  `store.state`, fetches the event JSON via `event_json_for_id`, and returns
  `{"chunk":[...]}`. Optional `membership` and `not_membership` query params
  filter the result. Conformance tests cover the happy path and unknown-room
  404.

### Production v1.0.0

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

#### TODO

- Keep real listener coverage in CI and prove the server serves requests until
  stopped by the service manager.
- Require configured TLS with validated certificate and private-key files for
  public listeners; keep loopback cleartext available for reverse-proxy
  deployments.
- Complete full Matrix v1.18 conformance, persistence, endpoint coverage, and
  production-grade rate limiting for client-server routes.
- Store access tokens only as versioned cryptographic hashes generated from
  LibSodium CSPRNG output.
- Store passwords only with LibSodium Argon2id password hashes.
- Enforce PostgreSQL transaction coverage, migration coverage, and role grants
  against real temporary databases.
- Fail closed when required production hardening controls are unavailable.
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- Add signed release artifacts, reproducible builds, dependency pinning
  policy, license review, provenance, and artifact signatures.
- Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and artifact signatures
  in release notes.

#### DONE

- Packaging files exist for Linux and BSD deployment-shape testing:
  `packaging/systemd/merovingian.service`, `packaging/openrc/merovingian`,
  `packaging/rc.d/merovingian`, and `Dockerfile`.
- Release-readiness script exists and rejects missing required release files or
  known unsafe legacy hashing primitives.
- Alpha prerelease publishing exists: `.github/workflows/release.yml` builds
  hardened Linux and FreeBSD tarballs for `v*-alpha*` tags, runs tests and
  release-readiness gates, emits SHA-256 checksum files, and publishes a
  GitHub prerelease.
- CodeQL, coverage, sanitizer, static-analysis, and Linux CI jobs install
  LibSodium development headers before configuring Meson.
- Federation request signing follows the Matrix-spec X-Matrix scheme: the
  signed payload is the canonical JSON object `{content?, destination, method,
  origin, uri}`, signed with the server's real Ed25519 secret key and verified
  against the remote's published `/_matrix/key/v2/server` public key. The prior
  shared-secret `verify_token` derivation — which could not interoperate with
  other homeservers — has been removed. PDU event signatures are verified via
  libsodium against known or on-demand-discovered keys; rotated keys trigger
  re-fetch through `make_persistent_remote_key_resolver` when `valid_until_ts`
  has passed or the `key_id` no longer matches, and the refreshed key is
  persisted before re-verification. Covered by unit and integration tests; a
  live interoperability test against an external homeserver is covered by
  `test_live_synapse_federation.cpp`, which exercises real TLS, DNS, and HTTPS
  against matrix.ping.me.uk and pong.ping.me.uk. The live suite is opt-in via
  `-Dbuild_live_tests=true` so the default integration target remains
  deterministic and repo-local.
- Federation auth parsing and signature verification failures intentionally
  return `502` instead of `401` on the federation HTTP surface. This prevents
  Synapse from propagating those failures back through a client-server request
  as `401 Unauthorized`, which Element can interpret as an invalid access token
  and convert into an automatic logout.
- Runtime users, tokens, rooms, events, account data, policy rules, federation
  destinations, federation transactions, local media, and remote media survive
  restart for both SQLite and PostgreSQL backends, verified by integration tests
  covering close/reopen cycles on all persisted data types.

## Immediate priority order

With the Alpha gates closed, Beta priorities take over from here:

1. Complete Matrix v1.18 conformance for client-server endpoints currently
   marked `partial` — promote them to `covered` with conformance fixtures.
2. Add Matrix federation conformance fixtures covering join, leave, invite,
   backfill, and key-rotation scenarios end to end.
3. Retire one hardening alpha exception per minor release — start with the
   ELF program-header probe (linker hardening / RELRO) and Linux
   seccomp-bpf filter. Update `docs/hardening-alpha-exceptions.md` when an
   exception lands.
4. Wire live remote media transport/server-discovery into the new remote-ingest
   boundary and replace thumbnail metadata with real resampling output.
5. Promote CI from build/test checks to full capability gates with
   conformance, fuzzing (already gated), platform, packaging, and signed
   release evidence.

## Capability ledger

| Capability | Current status | Evidence | Gap |
| --- | --- | --- | --- |
| Build and warning policy | `runtime-wired` | Meson C++26 build, warnings-as-errors, hardening flags, Linux and FreeBSD CI, reusable local build wrappers, unified `build.py` CLI (0.4.41) replacing `build-wsl.ps1`, WSL bridge wrapper, and named debug/release/sanitizer/coverage/fuzz/hardened wrapper profiles | Add signed release artifacts, reproducible builds, mandatory fuzz execution, and platform-specific production hardening enforcement. |
| Secure configuration | `runtime-wired` | Validated defaults, bounded parser, config-file metadata checks, reload planning, smoke tests | Replace phase-specific CI naming with capability gates and add production profile enforcement. |
| Runtime listener | `runtime-wired` | `net::TcpAcceptor` binds per `ListenerPlan`, `net::ShutdownSignal` handles SIGINT/SIGTERM, `homeserver::serve_http`/`serve_tls_http` accept/parse/dispatch loops, client listeners dispatch through the `client_server` Matrix JSON adapter, federation listeners dispatch through a federation-only router, default loopback federation bind avoids public reverse-proxy port `8448`, `--dry-run` flag for validation-only runs, integration tests exercising loopback HTTP and TLS round-trips | Add per-connection slowloris enforcement, per-endpoint rate-limit accounting, multi-listener thread pool, and keep-alive. |
| HTTP transport | `runtime-wired` | HTTP/1.1 request-head parser, request limits, rate-limit helpers, per-endpoint rate-limit enforcement keyed by normalized bucket, 429 `M_LIMIT_EXCEEDED` response on quota breach, single-request adapter, cleartext/TLS accept-read-write loop with response serialization, dispatch-mode separation, OpenSSL RAII boundary, libcurl-backed outbound HTTPS client with peer and hostname verification, redirects refused, https-only protocol, pinned-address DNS, bounded response cap, optional CA trust blob, and `MSG_NOSIGNAL` writes | Upgrade to `llhttp` or reviewed parser boundary, add request body streaming, keep-alive, HTTP/2, per-connection slowloris policy, remote-IP buckets for unauthenticated routes, durable rate-limit state, and operator-tunable policy overrides. |
| Client-server API | `runtime-wired` | Registration, password login, logout, whoami, devices, room creation with remote invite dispatch, send, joined rooms, `GET /rooms/{roomId}/members` with fallback synthesis (0.4.34), `GET /account/3pid` (0.4.34), `GET /pushers` (0.4.34), sync slices, unauthenticated `GET /_matrix/client/versions`, and Matrix v1.18-spec-complete sync response shape are reachable through the client listener's Matrix JSON adapter | Complete Matrix v1.18 endpoint coverage, conformance coverage, persistence semantics, and populate the top-level sync surfaces with real behavior. |
| Authentication and sessions | `runtime-wired` | LibSodium password hashing, CSPRNG access tokens, durable token hashes, SQLite/PostgreSQL hydration into runtime sessions, token-file-enforced public registration, UI-auth challenge for register (401 with flows/session when `auth` absent), explicit admin bootstrap API and startup flag, client-server register/login/logout/whoami/device/account-password routes, policy checks, durable audit events, and restart-survival coverage | Add richer operator bootstrap lifecycle controls, account recovery controls, and Matrix conformance fixtures for remaining auth flows. |
| E2EE key APIs | `runtime-wired` | Key API route/planning boundary, authenticated client-server runtime dispatch for upload/query/claim/cross-signing/signature/backup route shapes, durable device/one-time/fallback/cross-signing/signature/backup storage, one-time-key consumption, fallback-key reuse, room-sharing-driven `device_lists.changed` / `.left` publication, server-blind payload redaction, audit records, SQLite restart coverage, spec-correct `{"version":"1"}` response from `POST /room_keys/version` (0.4.31), working `DELETE /room_keys/version/{version}` removing the backup from the store and database (0.4.32), and conformance tests asserting delete+404 round-trip plus local `sendToDevice` / bootstrap behavior | Add full key-count algorithms, complete backup session retrieval/deletion, broader Matrix v1.18 semantics, and remaining conformance fixtures. |
| Rooms, events, and sync | `runtime-wired` | Strict canonical JSON parser boundary, deterministic serializer, event envelope, content hashes, reference-hash event IDs, redacted signing payloads, Base64 Ed25519 signature attachment/verification, persisted runtime signing key, signed runtime event JSON, durable event DAG rows, room-version-aware redaction, v6+ auth rules, state resolution v2, incremental sync with stream tokens and `since`, Matrix-shaped sync responses with `rooms.join`, `rooms.invite`, `rooms.leave`, and top-level `presence`, `account_data`, `to_device`, `device_lists`, and `device_one_time_keys_count` keys, encrypted-room policy, local room flow, and restart-survival integration coverage | Add sync long polling and filters, real payloads for presence/device/to-device/account-data surfaces, restricted join rule evaluation, third-party invite auth, and broader Matrix v1.18 room-version conformance fixtures. |
| Federation | `runtime-wired` | Runtime federation listener dispatch through a federation-only router, inbound transaction scaffold, unauthenticated inbound `GET /_matrix/key/v2/server` key publication with a canonical self-signed response, SSRF/TLS policy checks, trust-state logic, duplicate handling, canonical JSON Ed25519 request verification, JSON PDU event-signature verification for known and discovered remote keys, X-Matrix header parsing via `parse_x_matrix_authorization_header`, TLS-bound origin validation, signed-request integration coverage, server discovery with HTTPS well-known fetch, DNS SRV, A/AAAA resolution, IPv6 pins, private/loopback rejection, remote key fetch/cache with every listed verify key self-signed and rotation-triggered refresh via `make_persistent_remote_key_resolver`, outbound transaction types with exponential backoff and circuit breaker policy, `merovingian::http::OutboundClient`, `perform_outbound_transaction` wiring, `DispatchWorker` bounded retry queue, durable queue/destination persistence with restart replay at startup, X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, circuit-breaker short-circuit before network I/O, circuit-open requeue, inbound PDU/EDU ingestion hooks, all seven federation runtime callbacks wired (`pdu_sink`, `state_conflict_resolver`, `membership_template_provider`, `membership_acceptor`, `invite_handler`, `backfill_provider`, `remote_key_resolver`), inbound `send_join` membership state propagation, signed inbound invite persistence, remote-room join member hydration from `send_join` state, remote `createRoom` invite dispatch, and per-platform TLS integration coverage | Room-version-specific PDU verification, key rotation publication, multiple active/old keys, and Matrix federation conformance coverage. |
| Media repository | `runtime-wired` | Runtime media routes for authenticated local upload/download, MIME policy, quarantine/release/remove, LibSodium digest, metrics, audit, persistent metadata/blob writes, SQLite restart hydration, sandboxed processing worker boundary, AV hook boundary, decoder/decompression limits, remote-ingest boundary, thumbnail metadata, and integration coverage | Wire live remote media transport/server-discovery into the remote-ingest boundary, add real image thumbnail resampling, and carry true content headers through the local request model. |
| Database persistence | `runtime-wired` | Prepared-statement boundary, schema inventory, migration model, in-memory persistent store, SQLite RAII backend, current-schema bootstrap, fail-closed hydration, busy timeout, runtime hydration, write-through users/devices/tokens/rooms/events/E2EE keys/media/audit/admin/account-data/federation-queue/policy-rule/media-blob rows, SQLite transaction rollback, atomic runtime helpers, dependency reviews, PostgreSQL RAII connection/result boundary, PostgreSQL schema bootstrap/pending-migration hydration/write-through path, migration-file loading, offline migrator scaffold, database role separation, durable trust-and-safety rows, and restart-survival integration coverage | Add more live PostgreSQL integration tests and enforce runtime/migration grants through separate PostgreSQL users in deployment packaging. |
| Observability and audit | `runtime-wired` | Structured logging, health snapshots, safe metrics summaries, redaction helpers, durable audit events, admin health/metrics/audit runtime endpoints, and client-server action audit persistence | Add production scrape/export contract, log format contract, trace correlation, and operator docs. |
| Trust and safety | `runtime-wired` | Policy engine for registration, accounts, invites, federation, media, reports, and admin review routes, runtime client event reporting, admin safety report listing/review, durable policy audit rows, and durable admin action rows | Add Matrix v1.18 conformance fixtures, policy server transport integration, durable policy-rule management, and richer moderation workflows. |
| Runtime hardening | `integrated` | Systemd/OpenRC/rc.d packaging, hardening plan, startup self-check with `HardeningStatus::alpha_exception` + documented notes, `merovingian-server` refusing to bind when any control reports `disabled`, alpha-only exceptions enumerated in `docs/hardening-alpha-exceptions.md`, and release-readiness gating on the new doc | Implement the in-process probes that retire each documented alpha exception: ELF program-header probe for linker/RELRO status, Linux seccomp-bpf filter, OpenBSD pledge/unveil, FreeBSD Capsicum, optional in-process privilege drop, Landlock confinement, and `RLIMIT_CORE` clamp. |
| Platform support | `integrated` | Linux and FreeBSD CI, setup-command planning for OpenBSD and NetBSD | Add OpenBSD and NetBSD CI jobs, platform-specific runtime tests, and documented support tiers. |
| Fuzzing and conformance | `integrated` | Canonical JSON and HTTP fuzz targets build with `-fsanitize=fuzzer,address,undefined`, the `fuzz` GitHub Actions workflow runs each target for a bounded duration on every push (and longer on a Sunday schedule), and crash inputs/corpora are uploaded as artifacts | Add durable corpus management, broader Matrix conformance suite, property tests, load tests, and chaos tests. |
| Supply chain and release | `integrated` | Release-readiness script, installable `.deb`/`.rpm`/`.pkg` packages built by CI, Alpine/musl static Linux fallback tarball, tag-driven alpha prerelease workflow, SHA-256 checksums, alpha hardening exceptions documentation, plus dedicated secret-scan, dependency-vulnerability-triage, and SBOM workflows | Add dependency pinning policy, license review, artifact signing, provenance, and reproducible build notes. |

## Matrix v1.18 protocol coverage

An endpoint is not `covered` until it is runtime-wired, backed by durable state
where required, and checked by behavior tests or conformance fixtures.

Coverage states:

- `not-started`: no route or behavior exists.
- `planned`: route or boundary is identified, but there is no behavior.
- `scaffolded`: route or helper exists with placeholder behavior.
- `partial`: behavior works for a restricted local slice.
- `covered`: Matrix v1.18 behavior is implemented, tested, and documented.
- `blocked`: implementation depends on an unfinished lower-level capability.

The runtime listener binds configured client listeners and, when enabled,
federation listeners. Client listeners dispatch parsed HTTP/1.1 requests into
`handle_client_server_request` over loopback cleartext or configured TLS.
Federation listeners dispatch into a federation-only router that exposes only
federation requests and server-key publication. Internal compatibility paths can
still dispatch into the legacy local router until those surfaces have production
adapters.

### Client-server API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Authentication | `POST /_matrix/client/v3/register` | `spec-covered` | Matrix JSON body is parsed, registration-token UI auth is enforced from the configured token file, and empty `{}` registration probes now correctly return 401 with the `m.login.registration_token` flow, `params`, and a `session` token per Matrix UI-auth instead of a premature 400. When `inhibit_login` is absent or false the 200 response includes `access_token` and `device_id` per spec §5.5.1. Public registration creates non-admin users, local registration is reachable through the client listener, SQLite-backed local users survive restart, and happy-path plus UI-auth challenge cases are covered by the v1.18 fixture. Needs PostgreSQL coverage. |
| Authentication | `GET /_matrix/client/v3/register/available` | `spec-covered` | Unauthenticated username-availability probing now returns `{"available":true}` for free localparts and spec-shaped `M_USER_IN_USE` / `M_INVALID_USERNAME` errors for taken or invalid names. Runtime and Matrix v1.18 conformance coverage are in place. |
| Authentication | `GET /_matrix/client/v1/register/m.login.registration_token/validity` | `spec-covered` | Registration-token validity discovery now returns `{"valid":<bool>}` against the configured token file before the auth gate, with runtime and Matrix v1.18 conformance coverage for valid and invalid tokens. |
| Authentication | `POST /_matrix/client/v3/register/email/requestToken` | `spec-covered` | Homeserver-managed registration email validation now accepts Matrix request-token bodies, validates `client_secret` grammar plus the email address, creates an opaque `sid`, and reuses the same validation session for repeated attempts on the same triple. Runtime and Matrix v1.18 conformance coverage are in place. |
| Authentication | `POST /_matrix/client/v3/register/msisdn/requestToken` | `spec-covered` | Homeserver-managed registration MSISDN validation now accepts Matrix request-token bodies, validates `client_secret`, country code, and phone number, creates an opaque `sid`, and reuses the same validation session for repeated attempts on the same triple. Runtime and Matrix v1.18 conformance coverage are in place. |
| Authentication | `GET`/`POST /_matrix/client/v3/login` | `spec-covered` | Password login works for local users with LibSodium-backed hashes, token hashes are SQLite-persisted, GET login returns password-flow discovery, restart-survival is tested, and the v1.18 fixture covers password login with and without requested refresh-token support plus missing-type and empty-body edge cases. Fixed: INSERT SQL for device and access-token rows was missing parentheses (broke all logins). Needs PostgreSQL coverage. |
| Authentication | `POST /_matrix/client/v3/logout` | `spec-covered` | Local bearer-token logout works through the client listener, revokes the current token through the persistent store, and is covered by the v1.18 fixture with stale-token rejection. |
| Authentication | `POST /_matrix/client/v3/logout/all` | `spec-covered` | Runtime global logout revokes all user access and refresh tokens, marks active sessions revoked, appends durable auth audit, and is covered by the v1.18 client-server fixture. |
| Authentication | `POST /_matrix/client/v3/refresh` | `spec-covered` | Login issues a refresh token, `/refresh` rotates refresh/access tokens through persisted token hashes, revokes the old device access tokens, and is covered by the v1.18 client-server fixture with missing/reused refresh-token rejection. |
| Account | `GET /_matrix/client/v3/account/whoami` | `spec-covered` | Local token identity works through the client listener, is covered after SQLite restart, and is covered by the v1.18 fixture. |
| Account | `POST /_matrix/client/v3/account/password` | `spec-covered` | Authenticated password change validates the new value, hashes with Argon2id, and writes through to the in-memory runtime and the persistent store. Returns 401 without auth (`M_MISSING_TOKEN` when no bearer token is supplied, `M_UNKNOWN_TOKEN` when the token is present but unrecognised, per spec §5.7.2), 400 for weak passwords, and 200 on success. Covered by the v1.18 fixture and integration tests. Needs UI-auth re-authentication and `logout_devices` handling. |
| Devices | `GET /_matrix/client/v3/devices` | `spec-covered` | Device listing works through the client listener, is hydrated from SQLite devices, and is covered by the v1.18 client-server fixture. Needs Matrix device-list stream semantics. |
| Devices | `GET /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Runtime single-device fetch returns the Matrix device object or `M_NOT_FOUND` and is covered by the v1.18 client-server fixture. |
| Devices | `PUT /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Display-name update persists through the persistent store, updates the runtime mirror, appends durable audit, and is covered by the v1.18 client-server fixture with malformed-body rejection. |
| Devices | `DELETE /_matrix/client/v3/devices/{deviceId}` | `spec-covered` | Runtime deletion removes the device row, revokes that device's access and refresh tokens, marks active sessions revoked, appends durable audit, and is covered by the v1.18 client-server fixture. Needs full UI-auth delete-device fallback semantics. |
| Rooms | `POST /_matrix/client/v3/createRoom` | `spec-covered` | Local room creation works through the client listener, remote users listed in `invite` get signed outbound federation invites, and SQLite-persisted rooms survive restart. v1.18 fixture covers createRoom with name, visibility, and unauthenticated rejection; BDD coverage checks remote invite dispatch. Needs full create-room auth events and broader conformance fixtures. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/join` | `spec-covered` | Local join slice works through the client listener and membership writes route through the persistent store. v1.18 fixture covers join and leave for a second user. Needs federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/join/{roomIdOrAlias}` | `spec-covered` | Join-by-id delegates to the same local join handler as `/rooms/{roomId}/join` by rewriting the request target. Needs room-alias resolution, the `?server_name` hint, and federation-aware joins. |
| Rooms | `POST /_matrix/client/v3/rooms/{roomId}/send` / `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `spec-covered` | Local send slice works through the client listener with Matrix reference-hash event IDs, content hashes, persisted Ed25519 signatures, previous/auth event DAG rows, full v6+ auth checking against current room state before persistence, a spec-shaped PUT send alias covered by the v1.18 fixture with malformed-content rejection, and idempotent transaction IDs covered by the v1.18 fixture. Needs restricted join rule evaluation, third-party invite auth, and incremental sync completion. |
| Rooms | `GET /_matrix/client/v3/rooms/{roomId}/state` / `PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}` | `spec-covered` | Local state summary works through the client listener, state writes can arrive through the spec-shaped PUT state alias, and the PUT path is covered by the v1.18 fixture with name-setting and malformed-content rejection. Needs GET state route implementation, full state resolution semantics. |
| Sync | `GET /_matrix/client/v3/sync` | `spec-covered` | Sync returns Matrix v1.18-shaped JSON with event bodies in timelines, stream-token-based `next_batch`, incremental diffing when `since` is provided, and the full top-level envelope: `rooms` with `join`/`invite`/`leave`/`knock` maps, plus `presence`, `account_data`, `to_device`, `device_lists`, `device_one_time_keys_count`, and `device_unused_fallback_key_types`. The conformance suite now covers populated sync surfaces and joined/invited/left room envelope shapes in addition to the existing runtime, long-poll, filter, and incremental-sync tests. Needs wiring the stored `filter_id` query parameter to filter application, unread-notification/summary semantics, and durable stream tokens. |
| Sync | `POST /_matrix/client/v3/user/{userId}/filter` | `spec-covered` | Filter upload is runtime-wired through the client-server adapter, stores the filter JSON verbatim, returns an opaque `filter_id`, and is covered by the v1.18 fixture with cross-user rejection. Needs SQLite/PostgreSQL restart-survival coverage. |
| Sync | `GET /_matrix/client/v3/user/{userId}/filter/{filterId}` | `spec-covered` | Filter retrieval is runtime-wired, returns the stored filter JSON, and is covered by the v1.18 fixture with missing-filter rejection. Needs restart-survival coverage. |
| Account data | `PUT`/`GET /_matrix/client/v3/user/{userId}/account_data/{type}` | `spec-covered` | Global (non-room) account data is runtime-wired through the persistent store with an upsert, surfaces in `/sync`, and is covered by the v1.18 fixture with empty-body, missing-type, and cross-user rejection. Cinny stores `m.direct` here. Needs room-scoped account data (`/rooms/{roomId}/account_data/{type}`). |
| Discovery | `GET /_matrix/client/versions` | `spec-covered` | The unauthenticated spec discovery endpoint answers before the auth check with the versions array `v1.1` through `v1.18`, an empty `unstable_features` object, and v1.18 fixture coverage. Needs feature flags for unstable spec extensions once adopted. |
| Joined rooms | `GET /_matrix/client/v3/joined_rooms` | `spec-covered` | Joined-room list works through the client listener, is hydrated from SQLite memberships, and is covered by the v1.18 fixture. Needs full access checks. |
| Media | `GET /_matrix/media/v3/config` | `spec-covered` | Returns `m.upload.size` from the configured `security.media.max_upload_size` value and is covered by the v1.18 fixture. Cinny fetches this after login to know the maximum attachment size. |
| Media | `POST /_matrix/media/v3/upload` | `spec-covered` | Local authenticated upload, MIME checks, quarantine, digest, sandbox/AV/decoder/decompression processing boundary, thumbnail metadata, metrics, audit, metadata/blob persistence, and client-server JSON `content_uri` response are runtime-wired and covered by the v1.18 fixture with unauthenticated and malformed upload rejection. Needs multipart/content handling through real HTTP. |
| Media | `GET /_matrix/media/v3/download/{serverName}/{mediaId}` | `spec-covered` | Local download is reachable through the client-server adapter and covered by the v1.18 fixture with missing-media rejection. Remote ingest has a repository boundary but route-level live remote transport remains disabled/fail-closed. Needs real content headers once the local request model carries headers. |
| Media | `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}`, `GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` | `runtime-wired` | Thumbnail download returns 64x64 PNG thumbnails from the media repository for locally stored media. Returns 404 for missing thumbnails. Needs real image resampling, remote thumbnail fetch, and v1.18 conformance fixtures. |
| Receipts | `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}` | `runtime-wired` | Receipt endpoint parses `{receiptType}/{eventId}` from the path, federates `m.receipt` EDUs to remote servers in the room, updates local receipt state for `/sync`, and publishes sync notifications. Needs v1.18 conformance fixtures. |
| User directory | `POST /_matrix/client/v3/user_directory/search` | `runtime-wired` | User directory search returns matching profiles with case-insensitive substring match on displayname and user_id. Returns empty results for empty search terms. Needs v1.18 conformance fixtures. |
| E2EE keys | `PUT /_matrix/client/v3/room_keys/keys` | `spec-covered` | Batch key-backup PUT iterates `rooms` and `sessions`, stores each session individually, returns the Matrix v1.18 `RoomKeysUpdateResponse` (`count`, `etag`), and round-trips through encoded Matrix room/session path components used by later room-level and session-level GETs. Covered by v1.18 conformance fixtures for batch upload, overwrite-etag changes, encoded GETs, and bulk delete semantics. |
| Reports | `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}` | `spec-covered` | Authenticated event reports are runtime-wired through the client-server adapter, validated by the trust-and-safety policy engine, appended to durable policy audit rows, and covered by the v1.18 fixture with optional `reason`, ignored legacy `score`, and malformed-body rejection. Needs richer report storage/query semantics and joined-room membership enforcement. |
| E2EE keys | Device keys, one-time keys, fallback keys, cross-signing, backup APIs | `spec-covered` | Authenticated key API routes are runtime-wired through the client-server adapter with durable server-blind key storage, request-body-driven `/keys/query` and `/keys/claim`, one-time-key consumption, fallback-key reuse, `/keys/device_signing/upload`, `/keys/signatures/upload`, `/keys/changes`, `PUT /sendToDevice/{eventType}/{txnId}`, room-sharing-driven `device_lists.changed` / `.left`, full backup version/batch/room/session get-put-delete coverage, payload redaction, audit records, SQLite restart coverage, 64 KiB body limit, and percent-decoded room-key backup path handling. v1.18 fixtures now cover upload/query/claim, cross-signing publication, uploaded-signature propagation, malformed upload/query/claim rejection, local encrypted invite-accept bootstrap through `keys/changes` + `keys/query` + `keys/claim` + `sendToDevice` + `/sync to_device.events`, targeted local-device one-shot delivery, federated inbound `m.direct_to_device` delivery into `/sync to_device.events`, and restart-safe outbound to-device federation dispatch that preserves the client txn ID as the EDU `message_id`. Needs fuller one-time-key count behavior and broader multi-device/client interop fixtures. |
| Capabilities/push rules | `GET /_matrix/client/v3/capabilities`, `GET /_matrix/client/v3/pushrules/`, `GET /_matrix/client/v3/pushrules/global/`, `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}`, `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions`, `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled` | `spec-covered` | Authenticated clients receive minimal stable capability data plus a v1.18-shaped server-default push ruleset. The built-in GET surfaces now expose the full global ruleset, individual default rules, and their `actions` / `enabled` views. Covered by the v1.18 fixture; writable push-rule CRUD still needs implementation. |
| Profile | `GET /_matrix/client/v3/profile/{userId}` | `spec-covered` | Unauthenticated endpoint served before the access-token gate. Returns the stored displayname and avatar_url for the user, or 404 M_NOT_FOUND for unknown users. Covered by the v1.18 fixture including unknown-user 404 and post-update retrieval. |
| Profile | `GET /_matrix/client/v3/profile/{userId}/{keyName}` | `spec-covered` | Unauthenticated `getProfileField`; returns only the requested field (`displayname` or `avatar_url`). An unset or unknown field returns 404 M_NOT_FOUND. Covered by the v1.18 fixture and integration tests. |
| Profile | `PUT /_matrix/client/v3/profile/{userId}/displayname` | `spec-covered` | Authenticated update; cross-user attempts return 403 M_FORBIDDEN. Body must be a JSON object with a `displayname` field. Covered by the v1.18 fixture and integration tests. |
| Profile | `PUT /_matrix/client/v3/profile/{userId}/avatar_url` | `spec-covered` | Authenticated update; cross-user attempts return 403 M_FORBIDDEN. Body must be a JSON object with an `avatar_url` field. Covered by integration tests. |
| Discovery | `GET /_matrix/client/v1/auth_metadata`, `GET /_matrix/client/unstable/org.matrix.msc2965/*` | `partial` | Stable `auth_metadata` and the whole MSC2965 OIDC discovery namespace (`auth_metadata`, `auth_issuer`) now return 404 M_UNRECOGNIZED before the access-token gate when OIDC is unsupported. Cinny and Element probe these for OIDC support; the pre-auth 404 lets them fall back gracefully instead of producing a misleading 401. |
| VoIP | `GET /_matrix/client/v3/voip/turnServer` | `partial` | Returns an empty object and is covered by the v1.18 fixture. No TURN server is configured; an empty 200 lets clients disable VoIP gracefully. Needs real TURN credential issuance once VoIP is supported. |

### Federation API

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (inbound) | `partial` | Inbound transaction handling is runtime-wired through federation-only listener dispatch with request policy, duplicate handling, canonical JSON request-signature verification, JSON PDU event-signature verification for known and on-demand discovered keys with rotation-triggered refresh, X-Matrix header parsing, TLS-bound origin validation, PDU/EDU parsing, `pdu_sink` hook persisting PDUs to the durable store, `state_conflict_resolver` merging via state-resolution v2, and conflict audit. Outbound dispatch feeding this surface now also uses opaque restart-safe federation transaction IDs rather than local session counters, preventing false duplicate suppression after a restart. Needs richer EDU side effects, room-version-specific PDU verification, and conformance coverage. |
| Transactions | `PUT /_matrix/federation/v1/send/{txnId}` (outbound) | `partial` | `perform_outbound_transaction` composes the libcurl-backed `merovingian::http::OutboundClient` with X-Matrix Authorization through `make_federation_signature`, retry-state mutation through `apply_outbound_result`, and circuit-breaker short-circuit through `destination_should_retry`. `DispatchWorker` provides a bounded retry queue, requeues circuit-open transactions for the destination retry deadline, persists pending rows and destination retry state, and production startup replays pending rows before starting the worker. Per-platform TLS integration coverage exercises valid round-trip, hostname mismatch, untrusted self-signed, and 3xx rejection. Needs Matrix conformance coverage. |
| Joins/leaves/invites | Federation join, leave, invite, and backfill flows | `integrated` | `make_join`, `make_leave`, `make_knock`, `send_join` (v1+v2), `send_leave` (v1+v2), `send_knock`, `invite` (v1+v2), and `backfill` are dispatched through runtime hooks: `membership_template_provider` builds the event template, `membership_acceptor` persists the event, updates runtime membership for accepted joins/leaves, and returns auth-chain/state; `invite_handler` signs the invite event, persists local invite membership, and wakes sync; `backfill_provider` serves PDUs from durable rows. The `auth_chain` in the send_join response is now built by walking the `auth_event_ids` graph from current state events (BFS), not by dumping all room events — non-state events never appear in the chain. Unwired endpoints return 501. BDD callback coverage in `test_federation_runtime_callbacks.cpp`, auth-chain coverage in `test_federation_membership_endpoints.cpp`, and delivery coverage in `test_outbound_dispatch.cpp`. Needs full Matrix conformance fixtures and richer production leave/knock state semantics. |
| Server discovery | Well-known, DNS, TLS, and key discovery | `partial` | Server discovery now fetches `https://<server>/.well-known/matrix/server` through the pinned outbound client, parses `m.server`, falls back to `_matrix-fed._tcp.<host>` SRV records, resolves A/AAAA addresses, handles public IPv6 pins, rejects private/loopback IPv4 and IPv6 addresses before exposing the pin set to `OutboundClient`, and feeds remote key fetch/cache for on-demand inbound verification. Needs TLS-bound origin validation, richer Matrix edge-case fixtures, and live network conformance coverage. |
| Signing verification | Request and event signatures | `partial` | Federation requests are signed and verified with the Matrix-spec X-Matrix scheme: the signed payload is the canonical JSON object `{content?, destination, method, origin, uri}`, signed with the server's real Ed25519 secret key and verified against the remote's published public key. The prior shared-secret `verify_token` derivation has been removed. JSON PDUs verify Matrix event signatures against known or on-demand-discovered remote keys; `make_persistent_remote_key_resolver` re-fetches when `valid_until_ts` has passed or the `key_id` no longer matches. Remote server-key responses must self-sign every listed verify key before caching. TLS-bound origin validation rejects requests where the TLS peer name differs from the X-Matrix origin. Needs room-version-specific PDU hash verification, a live interoperability test against an external homeserver, and conformance coverage. |
| Profile query | `GET /_matrix/federation/v1/query/profile` (inbound) | `partial` | A signed inbound `query/profile` request is dispatched through the `profile_query_provider` runtime hook, which reads the local user's `displayname`/`avatar_url` from the persistent store. The optional `field` parameter restricts the response; unknown users return 404 `M_NOT_FOUND`; an unwired hook returns 501. BDD callback coverage in `test_federation_runtime_callbacks.cpp`. Needs `query/directory` and the remaining federation query endpoints, plus conformance fixtures. |
| E2EE key queries | `POST /_matrix/federation/v1/user/keys/query`, `POST /_matrix/federation/v1/user/keys/claim`, `GET /_matrix/federation/v1/user/devices/{userId}` (inbound) | `spec-covered` | Signed inbound E2EE key requests are dispatched through the `device_keys_query_provider`, `one_time_keys_claim_provider`, and `user_devices_provider` runtime hooks. The `key_query` module builds the canonical-JSON responses from the device-key, one-time-key, and cross-signing-key stores; `user/keys/claim` consumes one-time keys and reuses fallback keys; `user/devices` percent-decodes Matrix user IDs. Unit coverage in `test_federation_key_query.cpp`, signed route conformance coverage in `test_federation_conformance.cpp`, and dispatch/unwired coverage in `test_federation_runtime_callbacks.cpp`. Needs Matrix device-list stream semantics beyond these endpoint contracts. |
| Event-graph queries | `GET /_matrix/federation/v1/event/{eventId}`, `GET /_matrix/federation/v1/state/{roomId}`, `GET /_matrix/federation/v1/state_ids/{roomId}`, `POST /_matrix/federation/v1/get_missing_events/{roomId}` (inbound) | `partial` | Signed inbound event-graph queries are dispatched through the `event_query_provider`, `state_query_provider`, `state_ids_query_provider`, and `missing_events_query_provider` runtime hooks. The `event_query` module looks up single PDUs by ID and reads the persistent state/event tables for state and missing-event responses. `get_missing_events` filters by `min_depth` and caps by `limit`. The `auth_chain` walk is implemented for send_join responses via BFS over `auth_event_ids` from current state. Unwired hooks return 501. Unit coverage in `test_federation_event_query.cpp`. Needs historical state-at-event reconstruction and conformance fixtures. |
| Key publication | `GET /_matrix/key/v2/server` (inbound) | `spec-covered` | The federation HTTP surface answers unauthenticated key fetches with the persisted runtime Ed25519 verify key, `valid_until_ts`, populated `old_verify_keys` (all superseded keys with `expired_ts` capped at `now`), and a canonical self-signature. Response is pre-computed at startup and served lock-free from an atomic cache so Synapse's `ServerKeyFetcher` is never blocked by concurrent outbound calls. Covered by startup-cache, federation-surface reachability, remote-key self-signature verification/cache, and direct response-shape conformance fixtures. |
| Federation queues | Outbound federation and retry/backoff | `partial` | `OutboundClient` is wired through `perform_outbound_transaction` with retry-state mutation via `apply_outbound_result`, circuit-breaker short-circuit via `destination_should_retry`, and a `DispatchWorker` that retries discovery and delivery failures without dropping circuit-open transactions. Pending transactions persist to `federation_transactions`, destination retry state persists to `federation_destinations`, and production startup calls bounded worker replay before starting delivery. Needs live federation delivery coverage. |

### Server administration and operations

| Area | Endpoint or behavior | Status | Notes |
| --- | --- | --- | --- |
| Health | `GET /_merovingian/admin/health` | `partial` | In-process admin health exists and is reachable over the TCP listener via the legacy local router. Needs a real admin auth model, JSON response shape, and deployment checks. |
| Media moderation | Quarantine, release, remove, metrics | `partial` | Admin media actions exist locally with durable state, audit, and metrics. Needs richer authorization model and operator docs. |
| Trust and safety review | Reports and admin review | `partial` | Admin safety report listing and review actions are runtime-wired through authenticated client-server routes with durable policy audit and admin action rows. Needs policy rule management, Matrix v1.18 fixtures, and policy server transport. |
| Metrics | Exported metrics | `partial` | Admin metrics summaries are runtime-wired and avoid secret fields. Needs production scrape/export contract and trace correlation. |
| Debug logging | Redaction-aware diagnostic summaries | `partial` | HTTP dispatch, client-server auth/routing, room joins/events, event auth, persistent-store writes, and federation decisions emit structured debug diagnostics. `merovingian-server --debug` enables console diagnostics and `--log-file <path>` writes file diagnostics. `docs/debug-logging.md` documents join-failure triage and the redaction boundary. Needs production log-format contract and request trace correlation IDs. |

## Completed capability notes

### send_join response uses pre-join state snapshot (0.4.50)

- `send_join` response now returns room state **prior to** the new join event,
  as required by spec §11.5.1. Previously the join event was persisted before
  building `state` and `auth_chain`, so the joining user appeared as
  `membership=join` in the state array. Synapse uses the returned state to
  recalculate expected `auth_events` — finding the join event itself as the
  current member state produces a circular reference: Synapse calculates the
  join should reference itself, mismatches the claimed `auth_events`, and logs a
  WARNING. The fix snapshots state IDs before `store_event_with_state` and uses
  that pre-join snapshot for both arrays in the response. The join event itself
  is returned separately in the `event` field (v2) and is never included in
  `state` or `auth_chain`.
- Existing test corrected: the scenario that asserted `membership=join` in the
  `state` array was testing the wrong (buggy) behaviour. It now asserts
  `membership=invite` and also verifies the join event ID is absent from `state`.

### make_join create event excluded from auth_events (0.4.49)

- `make_join` template no longer includes `m.room.create` in `auth_events`
  for room version 12. In room v12 (MSC4291), the room ID is the reference
  hash of the create event; including it in auth_events is forbidden. Synapse
  asserts this at the Python level and returns 500 to its joining client even
  though `send_join` returned 200, producing a second error after the 0.4.48
  wire-format fixes. Gated via `RoomVersionPolicy::create_event_is_room_id`.
- One new conformance test added to `test_federation_invite_join.cpp` verifying
  the create event is absent from the template auth_events and the invite event
  is still present.

### Federated join wire format (0.4.48)

- `send_join` v2 response now includes the required `members_omitted: false`
  field. The Matrix spec marks this field as required; Synapse raises a
  `KeyError` when it is absent, returning `500 Internal Server Error` to its
  joining client and triggering an infinite `make_join`/`send_join` retry loop.
- `make_join` template `depth` is now set to `max(forward-extremity depths) + 1`
  instead of defaulting to `0`. Synapse used the template depth verbatim,
  producing join events at `depth=0` which fail state resolution.
- `make_join` template `prev_events` now contains only the room's current
  forward extremities (events not yet referenced as another event's
  `prev_events`), not all room events. The old bug inflated the state snapshot
  returned in every `send_join` response and caused incorrect state resolution
  at the joining server.
- Three new conformance tests added to `test_federation_invite_join.cpp` to
  guard all three bugs, covering response shape as well as processing side-effects.

### Federated invite-join auth chain (0.4.47)

- `membership_template_provider` now populates `auth_events` in `make_join`
  templates: `m.room.create`, `m.room.join_rules`, `m.room.power_levels`, and
  the joining user's current membership event (invite). Previously the template
  had empty `auth_events`, causing remote homeservers (e.g. Synapse) to reject
  the resulting join PDU with `403: You are not invited to this room`.
- `membership_acceptor` now copies `auth_event_ids` from the inbound PDU
  envelope to the persisted `PersistentEvent`. Without this, the BFS auth-chain
  walk could not follow links from the join event to the invite event.
- `invite_handler` now stores inbound invite events in `store.events` and
  `store.state` (in addition to `store.invites`), making them reachable during
  `send_join` auth-chain construction for the inbound-invite case.

### Federation key publication and discovery

- `GET /_matrix/key/v2/server` returns a canonical Matrix server-key object
  backed by the runtime Ed25519 signing key persisted in the local store.
- The key response includes `server_name`, `valid_until_ts`, `verify_keys`,
  `old_verify_keys` (all superseded keys with `expired_ts` capped at `now`),
  and a self-signature under `signatures`.
- The response is pre-computed during `start_runtime` and served lock-free
  from an atomic cache (`LocalDatabase::key_server_cache`), preventing
  Synapse's `ServerKeyFetcher` from timing out when a concurrent outbound
  request (e.g. `make_join`) holds the runtime mutex.
- HTTP listener dispatch no longer owns a separate process-wide lock. Client
  and local requests synchronize through `HomeserverRuntime::mutex`, and the
  remote join path releases that mutex before federation discovery and
  outbound membership calls so unrelated requests can continue while the join
  is waiting on the network.
- Server discovery now uses an injectable network boundary for behavior tests
  and a system implementation for well-known fetches, DNS SRV lookup, and
  A/AAAA resolution.
- Address pins are rejected before outbound use when any resolved address is
  loopback, private IPv4, IPv4 link-local, IPv6 unique-local, IPv6 link-local,
  IPv6 loopback, or IPv4-mapped private/loopback.

### Incremental sync foundation

- `merovingian::sync::StreamToken` stores hex-based `event_ordering` and
  `membership_ordering` fields with encode/decode/validate BDD coverage.
- `merovingian::core::SyncRequest` parses `since`, `timeout`, `full_state`,
  and `filter` query parameters.
- Schema migration v5 added `stream_ordering` columns to `events`,
  `membership`, and `invites`; added `membership` type to `membership`; and
  added `event_id` to `invites`.
- `PersistentEvent` and `PersistentMembership` include `stream_ordering`;
  `LocalDatabase` tracks `next_stream_ordering`.
- `sync_json` returns Matrix-shaped sync JSON with event bodies in timelines,
  stream-token-based `next_batch`, and incremental diffing.

### Outbound federation foundation

- `merovingian::federation::ServerDiscoveryResult` resolves server names from
  well-known delegation URLs, extracts host/port, rejects private IPv4/IPv6
  ranges, and validates server-name shape.
- `merovingian::federation::FederationDestination` tracks retry state for
  durable outbound queue processing.
- `merovingian::federation::OutboundTransaction` tracks pending PDUs/EDUs with
  method, target, origin, body, and retry metadata.
- `make_outbound_transaction()` constructs outbound transactions.
- `compute_backoff()` implements exponential backoff with a 2 second base and
  5 minute cap.
- `destination_should_retry()` opens the circuit after 3 consecutive failures
  and respects backoff expiry.

### Federation outbound HTTP and canonical responses

- `merovingian::http::OutboundClient` is a libcurl-backed HTTPS client for
  federation traffic. Requests run with peer verification, strict hostname
  verification, redirects refused, HTTPS-only protocol, signal-driven
  resolution disabled, explicit connect and total timeouts, bounded response
  body capture, and caller-supplied pinned addresses bound through
  `CURLOPT_RESOLVE`.
- `OutboundError` provides stable names for invalid URL/method, cleartext URL,
  unresolved host, TLS verification failure, connection failure, redirect
  rejection, oversized response, timeout, and generic network error.
- `OutboundCall` composes an outbound transaction with validated destination
  resolution and signing identity.
- `build_outbound_request()` builds the outbound HTTP request, including the
  `X-Matrix` Authorization header through `make_federation_signature`.
- `apply_outbound_result()` updates destination retry state after success or
  failure.
- `perform_outbound_transaction()` short-circuits when the circuit breaker is
  open, otherwise calls `OutboundClient::perform()` and applies the result.
- Per-platform TLS integration coverage drives a local TLS server through valid
  round-trip, hostname mismatch, untrusted self-signed certificate, and 3xx
  rejection scenarios.
- Client-server JSON responses now use `canonicaljson::Value` plus
  `serialize_canonical`; stored device-key payloads are parsed before
  re-serialization so malformed stored data surfaces as well-formed `null`.

## Single-server preview path

Before federation work completes, a closed test group can exercise the server as
a single homeserver with these caveats:

- No federation; users can only talk to users on the same instance.
- No remote media; local upload and download work, remote fetches fail closed.
- `GET /_matrix/client/versions` advertises `v1.1` through `v1.18` and empty
  `unstable_features`, so modern clients can proceed past discovery.
- E2EE can show unverified-device warnings until end-to-end verification,
  cross-signing, and key-sharing flows are proven.

## Release command sequence

```sh
sh scripts/setup-dev-env.sh --check-only
meson setup build -Dbuild_tests=true -Dbuild_fuzz=true
meson compile -C build
meson test -C build --print-errorlogs
sh scripts/reject-unsafe.sh
sh scripts/check-release-readiness.sh
git tag v<version>-alpha.1
git push origin v<version>-alpha.1
```

These commands are the minimum release evidence path. The release operator must
also record dependency versions, test logs, sanitizer logs, fuzz target names,
package checksums, and artifact signatures in release notes. Tags matching
`v*-alpha*` trigger `.github/workflows/release.yml`, which builds hardened
Linux and FreeBSD tarballs and publishes them as a GitHub prerelease, while
the published release event triggers `.github/workflows/sbom.yml` to attach
SPDX and CycloneDX inventories.
## 0.5.2 (in progress - codex/fix-local-invite-join-state)

- Fix local invite acceptance: invited local users no longer get inserted
  into `LocalRoom.members` before they have a `join` membership event.
  That bug made `POST /rooms/{roomId}/join` short-circuit as
  `room.join.already_member` while the room's current state still held the
  original invite event, leaving clients stuck in a half-joined state.
- Local join now persists a fresh `m.room.member` state event with
  `content.membership = "join"` before updating the membership row, so
  `GET /rooms/{roomId}/members` and `/sync` surface the accepted join
  instead of the stale invite.
- Runtime startup hydration now rebuilds in-memory room membership from
  persisted `join` rows only, so the same invite/member confusion does not
  return after restart.
- New BDD coverage in `tests/unit/test_client_server_conformance.cpp`
  asserts the invited local join transition, and the existing non-invite
  local join scenario now uses a `public_chat` room to match Matrix v1.18
  join rules.
- Follow-up conformance cleanup: success-path join coverage now uses a
  real `public_chat` room, the complement private-room join fixture
  explicitly invites Bob before he joins, and the client-server suite now
  asserts that uninvited joins to the default invite-only room are
  rejected with `403`.
- Follow-up review fix: runtime membership projection no longer erases a
  joined user when `invite` or `knock` membership updates are applied.
  A focused regression in `tests/unit/test_review_regressions.cpp` now
  pins that joined-members-only behavior.
## 0.5.5 (in progress — codex/fix-messages-eventid-and-preflight-rate-limit)

- `GET /_matrix/client/v3/rooms/{roomId}/messages` now serializes timeline
  events through the client event formatter instead of echoing raw stored event
  JSON. That restores required `event_id` fields in `chunk`, which real Matrix
  clients need to parse and decrypt encrypted room history correctly.
- Browser `OPTIONS` preflights now bypass client-server rate limiting. The
  runtime handles preflight before bucket accounting, so repeated cross-origin
  checks no longer consume the actual route quota or trip `429
  M_LIMIT_EXCEEDED` on the subsequent login, `/messages`, or media-config
  request.
- New strict regressions now pin both failures directly: a v1.18 conformance
  scenario asserts that `/messages` returns `event_id` on every room event in
  both `chunk` and `state`, and a runtime regression proves repeated
  preflights stay `200` and do not consume the target route's rate-limit
  bucket.
- Version metadata is bumped to `0.5.5` across Meson, the binaries, packaging
  manifests, and the packaging scripts for this PR.

## 0.5.4 (merged)
