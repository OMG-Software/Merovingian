# Changelog

## 0.1.61

- Finished Matrix v1.18 `/sync` conformance for the alpha:
  - Long polling now blocks on a `SyncNotifier` until a sync-relevant
    stream id advance (to-device, device-list change, presence, or
    account-data) or the request's `timeout` elapses.
  - Sync filter parser (`merovingian::sync::parse_filter_argument`)
    consumes inline JSON filters covering room include/exclude lists,
    `timeline.limit`, `senders`/`not_senders`, `types`/`not_types`,
    and `include_leave`. Filter ids are tolerated but ignored until
    server-side filter storage lands.
  - `presence.events` populated from the new `presence_state` table,
    keyed by per-user latest state and a monotonic stream id.
  - `account_data.events` populated for both the global scope and per
    joined room from the upgraded `account_data` table (now includes
    a `room_id` column added by schema migration v7).
  - `device_lists.changed` / `device_lists.left` populated from a new
    `device_list_changes` table observed by the syncing user.
  - `to_device.events` drains the new `to_device_messages` queue,
    addressing per-device or broadcast (`*`) targets and advancing the
    next-batch token's `sync_stream_id` past delivered rows.
  - `device_one_time_keys_count` reports per-algorithm OTK counts for
    the syncing device; `device_unused_fallback_key_types` exposes the
    matching fallback-key algorithm set.
- `StreamToken` gained a third `sync_stream_id` component so the
  next-batch encoding covers the new surfaces. Legacy two-segment
  tokens decode with `sync_stream_id == 0` for backwards compatibility.
- Schema bumped to v7 (`sync_surfaces_tables` migration): adds
  `room_id` to `account_data` and creates `to_device_messages`,
  `device_list_changes`, and `presence_state` tables.
- Added typed mutator helpers on `ClientServerRuntime`
  (`push_to_device_message`, `record_device_list_change`,
  `set_presence`, `set_account_data`) that publish through the
  notifier so long-polling sync waiters wake when sync-relevant state
  changes.
- Added BDD coverage for filter parsing, notifier wake/timeout
  semantics, and the populated sync response shape.
- Added a Complement-style integration fixture
  (`tests/fixtures/complement/sync_v1_18.json`) driven by a JSON
  runner; asserts the v1.18 sync response carries every documented
  top-level key.
- Bumped project and executable versions to `0.1.61`.

## 0.1.60

- Replaced the federation PDU state-conflict log-and-accept path with a
  state-resolution v2 merge:
  - `PduIngestionResult` now carries an optional `PduStateConflictContext`
    (room version + two conflicting state groups) that the sink populates on
    `rejected_state_conflict`.
  - `FederationRuntimeState::state_conflict_resolver` invokes
    `apply_state_resolution_v2` to merge the forks through Matrix
    state-resolution v2 and commit the result through a caller-supplied
    `ResolvedStateApplier`.
  - Successful merges count toward `pdus_appended`, emit a
    `federation.pdu_state_resolved` audit, and surface a
    `state_resolved=N` field in the transaction response. Failed merges
    fall back to the original `federation.pdu_state_conflict` audit and
    no longer count the PDU as accepted.
- Added inbound + outbound federation membership and history endpoints:
  - Inbound: `GET /_matrix/federation/v1/make_join|make_leave|make_knock`,
    `PUT /_matrix/federation/v{1,2}/send_join|send_leave`,
    `PUT /_matrix/federation/v1/send_knock`,
    `PUT /_matrix/federation/v{1,2}/invite/{roomId}/{eventId}`, and
    `GET /_matrix/federation/v1/backfill/{roomId}`. Each endpoint is
    dispatched through a typed hook on `FederationRuntimeState`
    (`membership_template_provider`, `membership_acceptor`,
    `invite_handler`, `backfill_provider`); endpoints without a wired
    hook return `501 Not Implemented` instead of pretending to succeed.
  - Outbound: `make_outbound_make_membership`,
    `make_outbound_send_membership`, `make_outbound_invite` (v1 and v2
    body shapes), and `make_outbound_backfill` produce
    `OutboundTransaction` records ready for `perform_outbound_transaction`
    and the dispatch worker.
  - `match_federation_route` now strips query strings, recognises the v1
    `send_join` / `send_leave` paths, and matches the new `make_*`,
    `send_knock`, and backfill routes including any `?ver=`, `?v=`, or
    `?limit=` query.
- `RuntimeFederationConfig` now carries `server_name`, surfaced into the
  backfill response so peers can attribute returned PDUs.
- Added BDD coverage for membership-path parsing, backfill query parsing,
  outbound helper composition, inbound `make_join` and `backfill`
  dispatch, fail-closed 501 behaviour when hooks are absent, and the
  state-resolution v2 merge helper.
- Bumped project and executable versions to `0.1.60`.

## 0.1.59

- Addressed PR #83 review feedback on the persistent outbound federation queue:
  - Serialised all `PersistentStore` mutations from the dispatch worker under
    the worker mutex. Persisting queue/destination state previously raced with
    `enqueue()` and corrupted the shared backing vectors.
  - PostgreSQL bootstrap now detects the Merovingian schema by probing for the
    `schema_migrations` table rather than any table in `public`, so a shared
    database with unrelated tables still initialises Merovingian's schema
    instead of failing later in `load_schema_state`.
  - Treat `delete_federation_transaction` failure after a successful HTTP send
    as a transport failure: the durable row stays in storage and the
    transaction is re-enqueued for retry instead of being silently re-sent on
    the next restart.
  - Treat `delete_federation_transaction` failure when dropping a max-retry
    row as a hard failure: the row is left in durable storage and surfaced as
    failed, so the next start replays it instead of silently dropping.
  - Treat `store_federation_transaction` failure on the retry/circuit-open
    paths as a hard failure: the in-memory transaction is not re-queued when
    durable state cannot be updated, preventing divergence between durable
    retry state and the live queue.
  - `replay_pending()` now parks rows beyond `max_queue_depth` in an internal
    overflow buffer and promotes them into the active queue as in-flight work
    completes, so a backlog larger than the in-memory cap is no longer
    stranded until the next restart.
- Added BDD coverage for replay overflow promotion under a bounded
  `max_queue_depth`.
- Bumped project and executable versions to `0.1.59`.

## 0.1.58

- Persisted outbound federation queue state:
  - Added durable store rows for federation destination retry state, including
    `retry_after_ts`, `last_success_ts`, and `consecutive_failures`.
  - Added durable outbound transaction rows with method, target, origin, body,
    retry count, and next retry timestamp for restart replay.
  - `DispatchWorker` can now replay pending rows from `PersistentStore`, persist
    enqueue/retry state, and remove delivered or dropped transactions.
  - Schema version `6` adds replay columns for existing federation queue tables.
  - PostgreSQL startup now applies pending schema migrations before hydration
    instead of recording new migrations during existing-schema bootstrap.
- Added BDD coverage for SQLite-backed federation queue replay after restart and
  dispatch worker replay of pending rows with destination backoff state.
- Bumped project and executable versions to `0.1.58`.

## 0.1.57

- Addressed PR #82 review feedback on alpha federation runtime hardening:
  - Unknown inbound remotes resolved through `remote_key_resolver` now upsert a
    full `FederationRemoteRuntime`, including discovery state, before the
    SSRF/TLS policy runs.
  - Remote key responses now reject any `verify_keys` entry without a matching
    valid self-signature, so unsigned extra keys are not cached as trusted.
  - The persistent remote-key resolver uses the real wall clock when no
    injectable clock is supplied, preventing expired cached keys from being
    treated as permanently fresh.
  - Dispatch worker `circuit_open` results are requeued for the destination's
    retry deadline instead of being dropped.
- Added BDD regression coverage for unsigned remote verify keys, on-demand
  inbound remote discovery seeding, and circuit-open dispatch requeue behavior.
- Bumped project and executable versions to `0.1.57`.

## 0.1.56

- Alpha tracker items 1, 3, and 4 of the federation milestone:
  - **Remote signing key fetch & cache.** New
    `federation/remote_key_cache` module fetches
    `GET /_matrix/key/v2/server` through the pinned
    `http::OutboundClient`, self-verifies the canonical Matrix key
    response with libsodium, persists keys to the existing
    `server_signing_keys` table, and exposes a refresh-aware resolver
    that plugs into `FederationRuntimeState::remote_key_resolver`.
    `FederationKeyRecord` now carries a raw `public_key_bytes` field for
    remote keys; `resolve_federation_public_key` chooses between the
    cached bytes and the local-server `verify_token` derivation.
  - **Outbound dispatch worker.** New
    `federation/dispatch_worker` module provides a `DispatchWorker`
    with a bounded mutex/condvar work queue, per-destination retry
    state, configurable max-retries/backoff, injectable clock and
    resolver hooks for deterministic tests, and a request_shutdown /
    drain / join lifecycle. The worker composes
    `perform_outbound_transaction` with `destination_should_retry` and
    re-enqueues failures honoring `compute_backoff`.
  - **Inbound PDU + EDU ingestion.** New
    `federation/inbound_ingestion` module parses canonical-JSON PDUs
    into ingestion envelopes (event id, room id, prev/auth events,
    depth, signatures) and classifies/validates EDU content for
    `m.typing`, `m.receipt`, `m.presence`, `m.direct_to_device`, and
    `m.device_list_update`. `handle_inbound_federation_request` now
    parses transaction bodies as `{ "pdus": [...], "edus": [...] }`
    JSON (with backwards-compatible single-PDU and legacy semicolon
    splits), drives an injected `PduSink` per accepted PDU, and an
    injected `EduSink` per accepted EDU. State-resolution conflicts
    surface as `federation.pdu_state_conflict` audit events and DO NOT
    abort the transaction — deferred state merge is a follow-up.
- BDD coverage for parse-and-verify (happy + tamper paths), cache
  shape checks, the refresh-slack window, the dispatch worker retry /
  drop / drain / queue-bound behavior, PDU envelope parsing, and EDU
  classification + per-type content validation.
- Bumped project and executable versions to `0.1.56`.

## 0.1.55

- Addressed PR #81 review feedback on federation server discovery:
  - **Honor explicit ports.** A `server_name` such as `example.org:7443` now
    resolves the host at the supplied port directly via A/AAAA, skipping both
    `.well-known` and `_matrix-fed._tcp` SRV lookup. Previously SRV could
    silently redirect federation traffic to a different host or port.
  - **Fall back on invalid `.well-known` bodies.** A 200 response with
    malformed JSON or a missing `m.server` member now continues into SRV and
    direct resolution rather than failing closed, matching the Matrix
    discovery algorithm.
  - **SRV on the delegated host.** When `m.server` supplies a hostname without
    an explicit port, discovery now attempts `_matrix-fed._tcp.<delegated>`
    before defaulting to port 8448, so delegated SRV indirection works.
  - **Bracket IPv6 literals in outbound URLs.** Federation outbound URLs now
    bracket IPv6 host literals so the port separator is unambiguous; without
    the brackets the URL was malformed and outbound transactions to IPv6-only
    peers failed.
- Bumped project and executable versions to `0.1.55`.

## 0.1.54

- Added unauthenticated inbound `GET /_matrix/key/v2/server` handling through
  the local federation router, backed by the persisted runtime Ed25519 signing
  key and a canonical self-signed Matrix key response.
- Implemented the server-discovery boundary for federation: HTTPS
  `.well-known/matrix/server` fetches, DNS SRV lookup for
  `_matrix-fed._tcp.<host>`, A/AAAA resolution, IPv6 address handling, and
  private/loopback rejection before addresses are exposed for outbound pinning.
- Added BDD coverage for key publication signature verification and discovery
  behavior across well-known, DNS SRV, public IPv4/IPv6 pins, and private
  address rejection.
- Updated `docs/01-progress-tracker.md` for the completed Alpha TODO items.
- Bumped project and executable versions to `0.1.54`.

## 0.1.53

- Consolidated production readiness, alpha/beta/production milestone tracking,
  alpha readiness, capability progress, and Matrix v1.18 protocol coverage
  into `docs/01-progress-tracker.md`.
- Updated release-readiness checks and project documentation links to use the
  consolidated tracker.
- Removed the superseded progress, protocol coverage, and production readiness
  tracker documents, including the alpha-readiness roadmap added on `main`.

## 0.1.52

- Addressed PR #79 review feedback from the automated reviewer:
  - **Per-identity rate-limit buckets.** `normalized_bucket` now
    prefixes the bucket key with the caller's access token so
    authenticated endpoints quota each client independently. The
    previous keying on method+target alone allowed a single bad
    actor with a few requests to throttle every other client on
    those endpoints. Unauthenticated routes (login, register,
    /_matrix/client/versions, /_matrix/key/v2/server) still share a
    global bucket per route; scoping those by remote IP is tracked
    as a follow-up that needs `LocalHttpRequest` to carry a
    `remote_addr` field.
  - **Sync invite cap.** `rooms.invite` is now capped at
    `rt.limits.max_sync_rooms`, matching the bound already applied
    to `rooms.join`. A user with many pending invites can no longer
    bypass the configured per-sync room limit.
  - **Default sync hides left rooms.** `rooms.leave` stays as an
    empty object for spec-shape completeness, but no left-room
    payload is emitted until the filter parser exists and the
    client opts in via `include_leave: true`. The previous code
    surfaced left rooms unconditionally which contradicted Matrix
    v1.18 default sync semantics.
- BDD tests added:
  - `Rate-limit buckets are scoped per access token to prevent
    cross-user denial of service` — alice exhausts her bucket, bob
    runs on his own and succeeds.
  - `the response keeps rooms.leave as an empty object until
    include_leave filter support lands`.
  - `the invite section honors the room cap and does not bloat the
    response`.

## 0.1.51

- Added `GET /_matrix/client/versions` — the unauthenticated spec
  discovery endpoint every Matrix client hits before login. Responds
  before the auth check with a `versions` array (v1.1 through v1.18)
  and an empty `unstable_features` object.
- Expanded `sync_json` to a Matrix v1.18-spec-complete response shape.
  `rooms.invite` and `rooms.leave` are now populated by walking
  `PersistentMembership` for entries matching the requesting user.
  Each invite carries an empty `invite_state.events`; each leave
  carries an empty `timeline` and `state`. Top-level `presence`,
  `account_data`, `to_device`, `device_lists`, and
  `device_one_time_keys_count` keys are emitted with empty payloads
  so clients can parse the response without falling back to spec
  defaults. The behaviour for those surfaces lands in later changes;
  the shape stays stable.
- Rate-limit enforcement now uses per-endpoint policies. `allow()` in
  `client_server.cpp` consults `http::endpoint_default_rate_limit` for
  the request's method and target, so login and register carry the
  tight 5-request quota, key and device APIs carry 30, media APIs 20,
  federation APIs 120, and the default falls back to 60. The runtime
  `ClientApiLimits::max_requests_per_bucket` acts as a ceiling on top
  of the policy so tests can drive the limiter from a single request.
  Quota breach returns 429 `M_LIMIT_EXCEEDED`. Window length stays in
  request-count units; switching the window to wall-clock seconds is
  deferred until an injectable time source is in place for tests.
- Added BDD coverage in `tests/unit/test_client_server.cpp`:
  unauthenticated /versions; sync surfacing invite/leave room
  categories plus the new top-level stubs; per-endpoint rate-limit
  enforcement (sixth registration in the window returns 429
  M_LIMIT_EXCEEDED, while another endpoint runs on its own bucket).

## 0.1.50

- Refreshed `docs/progress.md` Federation row evidence and production-gap
  text to reflect the libcurl-backed `OutboundClient`, the
  `perform_outbound_transaction` wiring, the per-platform TLS
  integration coverage, and the response JSON refactor. Replaced the
  outdated "Remaining outbound federation work" section with a current
  list of what still has to land for federation.
- Refreshed `docs/protocol-coverage.md`: split the Transactions row
  into inbound and outbound entries, moved the Federation queues row
  from `scaffolded` to `partial`, added a new `not-started` row for
  the missing inbound `GET /_matrix/key/v2/server` key publication
  endpoint, and updated Server discovery and Signing verification
  notes to reflect what the `OutboundClient` now provides.
- Added `docs/alpha-readiness.md` — the ranked roadmap from where the
  project is now to a federated alpha. Eight blockers with rationale,
  scope, effort, and current status; a cross-cutting parallel-work
  list; a single-server preview path for testers; and a rough
  end-to-end estimate.

## 0.1.49

- Phase A complete: replaced every hand-rolled JSON response in
  `src/homeserver/client_server.cpp` with the canonical JSON value
  model plus `serialize_canonical`. Affected response paths include
  `matrix_error`, `devices_json`, `joined_rooms_json`, `sync_json`,
  `safety_reports_json`, the `wrap` single-field helper, the device
  key and one-time key responses, and the register/login/whoami
  responses.
- Deleted the local `json_escape` helper. Its replacement is the
  canonical serializer, which correctly emits `\u00XX` for U+0000..U+001F
  control characters and validates UTF-8 — closing the latent gap in
  the previous hand-rolled escaper.
- Added a thin builder facade (anonymous-namespace helpers
  `json_str`, `json_int`, `json_bool`, `json_arr`, `json_obj`,
  `json_member`, `json_serialize`, `json_embed_raw`) over
  `canonicaljson::Value` so response paths read as a value tree rather
  than as string concatenation. The facade is internal to
  `client_server.cpp` for now; it can be extracted to a header once a
  second caller needs it.
- Device key and one-time key responses embed the stored key payload
  through `json_embed_raw`, which parses the blob with the canonical
  parser before re-serialization. Invalid or non-UTF-8 stored payloads
  now surface as `null` in the response rather than producing
  malformed JSON on the wire.
- Response key ordering switches from hand-rolled insertion order to
  the canonical lexicographic order. Existing tests verify substrings,
  not key positions, so the on-wire shape stays equivalent for every
  consumer.

## 0.1.48

- Added an optional `trusted_ca_pem` field to `OutboundRequest`. When empty
  the system trust store stays in effect; when populated the PEM blob is
  attached via `CURLOPT_CAINFO_BLOB` so tests and pinned-CA deployments
  can trust a specific certificate without writing it to disk.
- Added `tests/integration/test_federation_outbound_flow.cpp`: spins up a
  one-shot TLS test server backed by `merovingian::homeserver::TlsServerContext`
  with a self-signed CN=localhost certificate and drives
  `OutboundClient::perform` against it through four scenarios. Valid cert
  + matching hostname + trusted CA round-trips a 200 response; a mismatched
  hostname fails with `tls_verification_failed`; an empty trust bundle
  fails with `tls_verification_failed`; a 302 response surfaces as
  `redirect_rejected` with the redirect status preserved on the result.
- Updated `docs/json-output-and-http-client-hardening.md` to mark Phase B
  slice 3b complete.
- `tests/integration/test_main.cpp` now ignores `SIGPIPE` at process
  startup so the integration test process is not killed when a TLS peer
  closes the connection during handshake or before the server thread's
  next write. Failures continue to surface through return codes.

## 0.1.47

- Wired `merovingian::http::OutboundClient` into the federation outbound
  path. Added `OutboundCall` (composed transaction + validated
  resolution + signing identity), `build_outbound_request` (pure URL,
  header, and body builder), `apply_outbound_result` (updates the
  destination retry state and last_success_ts based on the result), and
  `perform_outbound_transaction` (single-attempt wrapper that
  short-circuits to `circuit_open` when `destination_should_retry`
  rejects the attempt and otherwise calls `client.perform`).
- The X-Matrix Authorization header is built through
  `make_federation_signature` so outbound and inbound speak the same
  signing primitive.
- Federation outbound requests inherit all libcurl security defaults
  from slice 2: peer + hostname verification, redirects refused,
  https-only protocol, signal-driven resolution disabled, explicit
  timeouts, response body cap, and CURLOPT_RESOLVE-pinned DNS.
- Added BDD coverage for the request builder (URL composition, method,
  body, pinned addresses, Authorization and Content-Type headers), for
  retry-state mutations on success and on multiple failure modes
  (transport error, non-2xx response), and for circuit-breaker early
  return without any network I/O.
- Reordered `src/meson.build` so `http_lib` is defined before
  `federation_lib`; updated `src/federation/meson.build` to link
  `http_lib` and declare `libcurl_dep`.
- Updated `docs/json-output-and-http-client-hardening.md` to mark Phase
  B slice 3 complete and document slice 3b (local TLS integration
  test harness) as the remaining piece.

## 0.1.46

- Implemented the libcurl-backed `perform()` on
  `merovingian::http::OutboundClient`. Each request runs with peer
  verification on (`CURLOPT_SSL_VERIFYPEER=1`), strict hostname
  verification on (`CURLOPT_SSL_VERIFYHOST=2`), redirects refused
  (`CURLOPT_FOLLOWLOCATION=0`), the protocol restricted to https
  (`CURLOPT_PROTOCOLS_STR="https"`), explicit connect and total timeouts,
  and signal-driven resolution disabled.
- Pinned DNS for the request URL to the caller-supplied
  `pinned_addresses` via `CURLOPT_RESOLVE` so the connection cannot
  drift to a different address after the federation security policy has
  validated the destination.
- Mapped libcurl failure modes onto `OutboundError`:
  `tls_verification_failed`, `connection_failed`, `timeout`,
  `response_too_large`, and a default `network_error`. A 3xx response
  surfaces as `redirect_rejected` with the status and headers preserved
  on the result for audit.
- Capped response body capture at `max_response_body_bytes`. Oversized
  responses abort the transfer and report `response_too_large`.
- Replaced the `not_implemented` stub error with the network-level error
  set. Updated tests to cover the new error names and the pre-network
  fail-closed behavior for cleartext URLs, missing pinned addresses, and
  unknown HTTP methods.
- Updated `docs/http-transport.md` and
  `docs/json-output-and-http-client-hardening.md` to reflect Phase B
  slice 2 completion.
- Propagated the libcurl dependency through `scripts/setup-dev-env.sh`,
  `scripts/wsl-setup.sh`, `scripts/build-linux.sh`, `scripts/build-bsd.sh`,
  the `Dockerfile` (build and runtime layers), and the CI workflows
  (`ci.yml`, `codeql.yml`, `coverage.yml`, `sanitizers.yml`,
  `static-analysis.yml`). The FreeBSD CI lane adds `curl` to its
  `pkg install` line.
- Added `docs/dependencies/libcurl.md` recording the dependency review;
  added the row to `docs/dependencies/index.md`, mentioned libcurl
  headers in `docs/dev-environment.md`, and added the new doc to
  `scripts/check-release-readiness.sh`.

## 0.1.45

- Added foundation slice of the federation outbound HTTP client:
  `merovingian::http::OutboundClient`, `OutboundRequest`, `OutboundResponse`,
  `OutboundResult`, and `OutboundError`. The slice introduces the public
  surface and a fail-closed `perform()` returning `not_implemented` so
  callers cannot mistake the result for a successful network round trip.
- Added `validate_outbound_request`: a pure validator that rejects unknown
  HTTP methods, cleartext URLs, malformed URLs, and requests without
  caller-pinned addresses. Keeps the SSRF policy in
  `merovingian::federation::security` as the single source of truth.
- Added BDD test coverage for outbound validation, stub fail-closed
  behavior, and stable audit-friendly error naming.
- Added `libcurl` (>= 7.85.0) as a build dependency wired into `http_lib`.
  The TLS backend is whatever the system libcurl was built against; a
  `subprojects/curl.wrap` fallback is deferred until a known-good WrapDB
  release is pinned.
- Updated `docs/http-transport.md` and
  `docs/json-output-and-http-client-hardening.md` to record the slice 1
  surface and the work remaining in slices 2 and 3.

## 0.1.44

- Fixed `store_room_with_membership` inserting only 2 columns into the 4-column
  `membership` table (missing `membership` and `stream_ordering`), causing
  `createRoom` to fail at runtime.
- Fixed SQLite and PostgreSQL hydration queries to select all columns from
  `membership` (4 cols) and `events` (6 cols) tables, preserving
  `stream_ordering` across restarts.
- Fixed sync JSON leaking raw event content (`m.room.encrypted`, `secret`);
  now outputs bounded summaries with only `event_id` and `sender`.

## 0.1.43

- Fixed missing v5 migration record in `initialize_current_schema` (SQLite)
  and `postgresql_schema_bootstrap_statements` (PostgreSQL): fresh databases
  now correctly record the `stream_ordering_and_membership_columns` migration,
  preventing schema validation failure on startup.
- Fixed sync JSON response missing `event_count` field that caused
  `run_client_server_flow` to fail.
- Fixed version string in `main.cpp` and `db_migrate.cpp` to match meson
  project version (0.1.43).
- Updated schema version test assertion from `4U` to `5U`.
- Added `005_stream_ordering_and_membership_columns.sql` migration file.

## 0.1.42

- Fixed meson subdir ordering: `rooms_lib` must be defined before `events_lib`
  can reference it.
- Added missing `#include <algorithm>` for `std::reverse` in `stream_token.cpp`.
- Fixed `test_client_server.cpp`: qualified
  `merovingian::homeserver::handle_client_server_request` namespace,
  added `json_value` helper for incremental sync tests, removed extraneous
  closing braces.

## 0.1.41

- Added outbound federation module: `OutboundTransaction` struct for tracking
  pending PDUs/EDUs to remote servers, `make_outbound_transaction` factory,
  exponential backoff with cap (`compute_backoff`), and circuit breaker retry
  policy (`destination_should_retry`).
- Added server discovery module: `ServerDiscoveryResult` for resolving server
  names, well-known delegation, and private IP rejection; `FederationDestination`
  struct for retry state persistence.
- BDD test coverage for outbound transaction creation, backoff computation,
  circuit breaker behavior, and server discovery validation.

## 0.1.40

- Added BDD test coverage for sync endpoint: initial sync returns stream
  token and event bodies; incremental sync with since token returns new
  events without duplicates.
- Sync route now uses starts_with to support query parameters.

## 0.1.39

- Added stream token type for incremental sync: encode/decode hex-based
  `event_ordering_membership_ordering` tokens that represent a position in the
  event stream.
- Added `sync` library with `StreamToken`, `encode_stream_token`,
  `decode_stream_token`, and `is_valid_stream_token` functions.
- Added `core::SyncRequest` and `core::parse_query_params` for extracting
  `since`, `timeout`, `full_state`, and `filter` from `/sync` query strings.
- Added `core::percent_decode` for URL percent-decoding sync filter values.
- Rewrote `sync_json` to produce Matrix v1.18-compliant sync responses with
  actual event bodies in timelines, stream-token-based `next_batch`, and
  incremental diffing when a `since` token is provided.
- Schema migration v5: added `stream_ordering` column to `events` and
  `membership` tables, `membership` column to `membership` table, and
  `event_id` + `stream_ordering` columns to `invites` table.
- Added `stream_ordering` field to `PersistentEvent` and `PersistentMembership`
  structs; `LocalDatabase` tracks `next_stream_ordering` for monotonically
  increasing event stream positions.
- Updated `store_event`, `store_event_with_state`, and `store_membership` to
  persist stream ordering and membership type.
- BDD test coverage for stream tokens, query parameter parsing, URL
  percent-decoding, and updated migration count assertions for v5.

## 0.1.38

- Fixed event authorization for room bootstrapping: the room creator is now
  implicitly treated as joined with power level 100 when no sender_member
  or power_levels event exists in the auth event map.
- Fixed self-join ban check: banned users are now correctly rejected by
  checking the target's membership rather than the sender's membership,
  resolving a false-allow when sender_member is absent but target_member
  records a ban.
- Fixed target_current_membership resolution for self-joins: when sender
  equals state_key, the sender_member is now used as the authoritative
  target membership if available.
- Made event auth check conditional on the presence of a create event in
  room state, allowing the simplified room creation flow to send events
  without auth rejection before a formal m.room.create state event exists.
- Added `effective_sender_power` helper to compute sender power level with
  creator-default-100 fallback when no power_levels event exists.

## 0.1.37

- Implemented full Matrix v6+ event authorization rules (14-step algorithm
  per spec section 10): create event validation, sender-domain matching,
  member join/invite/leave/ban with join-rule and power-level checks,
  power-level elevation guard, state-default and events-default enforcement,
  and redact power checks.
- Implemented v2 state resolution algorithm: conflicted/unconflicted state
  partition, reverse topological power sort, mainline ordering for
  power-level event ties, and iterative auth-based conflict resolution.
- Added `AuthEventMap` for building auth event context from current room state.
- Wired auth checking into the event sending path: composed events are
  authorized against current room state before persistence.
- Added helper functions for power-level extraction, membership state parsing,
  sender domain extraction, and content membership reading.
- Added `MembershipState::ban` to the membership state enum.
- Added comprehensive BDD test coverage for auth rule steps, join rules,
  power levels, kick/ban/invite flows, and v2 state resolution conflict
  scenarios.

## 0.1.36

- Replaced deterministic signing-key derivation with cryptographically random
  Ed25519 keypair generation so the runtime signing secret cannot be
  reconstructed from public server identity values (P1 fix).
- Required full Ed25519 event-signature verification for all PDUs when a
  signing key is available; comma-delimited PDUs without JSON are now
  rejected rather than bypassing cryptographic verification (P1 fix).
- Fixed `origin_server_ts` to use wall-clock Unix-epoch milliseconds
  instead of the sequential depth counter, conforming to the Matrix
  specification (P2 fix).
- Added `depth` column to the `events` table so event depth survives
  server restarts instead of regressing to zero (P2 fix).
- Extended `server_signing_keys` with a `server_name` column and composite
  primary key so key lookups are scoped to server identity, preventing
  cross-server key confusion after a `server_name` change (P2 fix).
- Added schema version `4` migration for the new `depth` and `server_name`
  columns and updated SQLite/PostgreSQL hydration and bootstrap.
- Added BDD coverage for random signing keys, depth persistence,
  server-scoped key lookups, comma-delimited PDU rejection, and
  wall-clock `origin_server_ts`.

## 0.1.35

- Removed the tracked `subprojects/yyjson` gitlink so CI and local clean
  checkouts use the pinned `yyjson.wrap` fallback plus the project-owned Meson
  package file.
- Ignored Meson-downloaded yyjson subproject checkouts and Python bytecode
  caches to keep generated dependency artifacts out of commits.
- Aligned CLI version output with the Meson project version for CI smoke tests.

## 0.1.34

- Runtime-wired authentication/session audit durability, admin metrics/audit
  summaries, and trust-and-safety report/review routes through the
  client-server runtime.
- Added named Linux/BSD/WSL build profiles for debug, release, sanitizer,
  coverage, fuzz, and hardened builds.
- Promoted authentication and sessions, database persistence, observability and
  audit, trust and safety, and build/warning policy to `runtime-wired` in the
  progress ledger with remaining production gaps documented.

## 0.1.33

- Fixed runtime state-event materialization so Matrix state events are detected
  by the presence of `state_key`, including the valid empty-string state key.

## 0.1.32

- Moved dependency reviews into `docs/dependencies/` and added reviews for
  LibSodium, OpenSSL, SQLite, yyjson, and Catch2 alongside PostgreSQL libpq.
- Added release-readiness checks for the dependency-review documentation set.

## 0.1.31

- Routed Linux, sanitizer, coverage, static-analysis, CodeQL, and FreeBSD CI
  builds through reusable local build wrappers.
- Added a FreeBSD build wrapper and Ubuntu/Debian WSL setup script that installs
  the native dependencies plus a current Meson/Ninja virtualenv.

## 0.1.30

- Fixed federation inbound-request compilation under CI warning-as-error builds
  by naming the intentionally unused request-signing key ID parameter,
  constructing owned signing-key IDs, and including the event-ID API.

## 0.1.29

- Confirmed OpenSSL as the TLS provider behind Merovingian's project-owned TLS
  boundary and kept the pinned WrapDB fallback for bootstrap builds.
- Clarified that GnuTLS is not the active replacement path while WrapDB lacks a
  standard `gnutls` package for this project to consume.

## 0.1.28

- Added a pinned OpenSSL WrapDB fallback so TLS builds no longer require a
  system OpenSSL package when Meson fallback downloads are enabled.
- Documented the GnuTLS tradeoff: it can be considered as a TLS provider, but
  there is no standard WrapDB `gnutls` package to consume directly.

## 0.1.27

- Wired runtime-created room events through persisted server signing keys, Matrix
  content/reference hashes, Ed25519 signatures, and reference-hash event IDs.
- Persisted local event DAG rows for previous events, auth events, and event
  signatures during runtime event writes, with SQLite/PostgreSQL hydration.
- Replaced federation request-signature scaffolding with canonical JSON
  Ed25519 verification and added JSON PDU event-signature verification for
  known remote signing keys.

## 0.1.26

- Replaced event ID scaffolding with Matrix reference-hash event IDs for modern
  room versions using SHA-256 and URL-safe unpadded Base64.
- Added Matrix content-hash calculation that excludes `unsigned`, `signatures`,
  and `hashes` before canonical JSON hashing.
- Redacted events before signing, stored Ed25519 signatures as Matrix unpadded
  Base64, and added verification against the signed canonical payload.

## 0.1.25

- Added schema version `3` for durable E2EE key storage tables covering device
  keys, key signatures, key backup versions, and key backup sessions.
- Added persistent-store helpers and SQLite/PostgreSQL hydration for device
  keys, one-time keys, fallback keys, cross-signing keys, signatures, key
  backup versions, and key backup sessions.
- Wired `/keys/upload`, `/keys/query`, and `/keys/claim` to persisted
  server-blind key state, including one-time-key consumption and fallback-key
  reuse after restart.
- Aligned executable version banners with the Meson project version and kept
  migration-plan validation coverage independent from current-schema coverage.

## 0.1.24

- Runtime-wired authenticated E2EE key API route handling through the
  client-server Matrix JSON adapter while keeping uploaded key payloads
  server-blind and redacted from runtime records/audit summaries.
- Promoted the progress ledger for E2EE key APIs, rooms/events/sync,
  federation, and the media repository to `runtime-wired` with current
  production gaps documented.
- Updated Matrix protocol coverage notes for the newly wired key API route
  slice and existing runtime wiring evidence.

## 0.1.23

- Resolved the PostgreSQL persistence branch merge with the SQLite transaction
  hardening already on `main`.
- Marked `libpq` headers as system includes and installed PostgreSQL client
  development packages in CI workflows.
- Made the database executor base movable so the RAII PostgreSQL connection can
  be returned by value without deleting its move operations.

## 0.1.22

- Wired PostgreSQL persistent-store bootstrap and row hydration behind the
  `libpq` boundary when a PostgreSQL URI file is explicitly configured.
- Added write-through PostgreSQL transaction execution for persistent-store
  mutations.
- Added physical SQL migration file loading and an offline
  `merovingian-db-migrate` planning scaffold.
- Added database runtime/migration role separation through `database.role`.
- Added explicit PostgreSQL integration-test gating through
  `MEROVINGIAN_TEST_POSTGRESQL_URI`.

## 0.1.21

- Marked the OpenSSL dependency include path as a system include so FreeBSD
  CI does not fail project warning-as-error gates on OpenSSL header macros.
- Added a reviewed `libpq` dependency boundary for PostgreSQL support.
- Added PostgreSQL connection-string policy and redacted connection summaries
  so password material is not exposed in diagnostics.
- Added RAII wrappers for PostgreSQL connections and command results using
  `PQfinish` and `PQclear`.
- Added parameterized PostgreSQL statement execution through `PQexecParams`
  behind the existing prepared-statement validation boundary.

## 0.1.20

- Added persistent-store transaction helpers so login device/token writes, room
  creation membership writes, and event/current-state writes commit atomically.
- Added SQLite backend transaction rollback coverage for failed statement
  groups.
- Changed SQLite startup hydration to fail closed when row queries cannot be
  prepared or stepped to completion.
- Set a busy timeout on SQLite connections and removed the FreeBSD
  warning-as-error failure caused by the `SQLITE_TRANSIENT` macro cast.

## 0.1.19

- Added an SQLite-backed persistent store with RAII connection/statement
  wrappers, current-schema bootstrap for new database files, row hydration at
  startup, and write-through persistence behind the existing database boundary.
- Hydrated runtime users, sessions, rooms, memberships, events, and client
  device listings from persisted SQLite rows when the homeserver restarts.
- Added integration coverage proving a SQLite-backed runtime can register,
  login, create a room, send an event, restart, authenticate the old token, and
  expose the persisted room state.
- Changed auth and room runtime mutations to fail the operation when the
  backing persistent store rejects required writes.
- Fixed the unsafe source gate regex literals so CI rejects banned allocation
  APIs instead of treating malformed grep patterns as success.

## 0.1.18

- Added an OpenSSL-backed TLS server boundary with RAII context and connection
  wrappers, handshake timeouts, TLS 1.2 minimum protocol enforcement, and
  fail-closed certificate/key loading.
- Wired TLS listener plans into the runtime accept loop so `listeners.*.tls=true`
  can serve the existing HTTP Matrix JSON adapter instead of being rejected at
  startup.
- Added listener TLS certificate/private-key configuration keys, validation,
  reload planning, secure file metadata checks, and loopback TLS integration
  coverage.

## 0.1.17

- Marked the pinned `yyjson` fallback include directory as a system include so
  project warning-as-error policy does not fail CI on third-party C header
  implementation details.
- Moved direct `yyjson.h` inclusion behind a C adapter so C++ static analysis
  does not parse third-party C inline implementation details.
- Updated the server version smoke test to assert `meson.project_version()`
  instead of a stale literal.
- Bounded clang-tidy CI to changed translation units with parallel per-file log
  groups and timeouts; headers remain covered transitively through compile
  commands.

## 0.1.16

- Added `yyjson` as the strict JSON parser dependency with a pinned Meson wrap
  fallback.
- Replaced the hand-written canonical JSON parser with a `yyjson` adapter that
  copies into the project-owned `canonicaljson::Value` model.
- Kept Matrix canonical JSON policy in Merovingian by rejecting duplicate keys,
  floats, exponent numbers, and unsigned values outside the signed 64-bit range
  during adapter conversion.

## 0.1.15

- Routed client listener traffic through the Matrix JSON client-server adapter
  while preserving local-router dispatch for federation/internal compatibility
  paths.
- Added loopback integration coverage proving TCP listener registration accepts
  Matrix JSON request bodies.
- Updated progress, protocol coverage, HTTP transport, and production-readiness
  docs for the client-listener dispatch change.

## 0.1.14

- Wired the `merovingian-server` binary to actually serve traffic: it now opens TCP listeners for the configured client (and federation, when enabled) binds, accepts HTTP/1.1 connections, parses request heads through the existing transport limits, and dispatches them to the local HTTP router.
- Added `merovingian::net::TcpAcceptor` (RAII TCP listening socket via `getaddrinfo`, `SO_REUSEADDR`, `IPV6_V6ONLY`, `getsockname`-reported bound port) and `merovingian::net::ShutdownSignal` (signal-safe self-pipe + SIGINT/SIGTERM handler installer; pinned to its construction site because the registered handler holds its address).
- Added `merovingian::homeserver::serve_http`, a single-threaded-per-acceptor accept/parse/dispatch loop that serialises shared runtime mutation through a caller-provided mutex and respects the existing `http::RequestLimits`.
- Added a `--dry-run` CLI flag that runs config validation and prints the startup summary without binding any listeners; previous smoke tests now opt in via `--dry-run`.
- TLS listeners (`tls=true`) fail closed at startup with a "TLS not yet implemented" error until the crypto stack is in place.
- New exit codes `runtime_start_error` (80) and `listener_error` (81) for failures after configuration validation.
- New BDD coverage: `test_tcp_acceptor`, `test_shutdown_signal`, and `test_http_server_listener_flow` (end-to-end loopback HTTP exchange against a started runtime).

## 0.1.13

- Added authoritative capability progress tracking and Matrix v1.18 protocol
  coverage documents.
- Marked numbered phase and milestone documents as historical tracking notes.
- Updated CI artifact and release-readiness checks to require the current
  progress documents.

## 0.1.12

- Update release readiness and CI artifact paths after numbering the
  production-readiness document.
- Remove clang-tidy-blocked `reinterpret_cast` calls from token and media
  digest input handling.

## 0.1.11

- Install LibSodium development headers in CodeQL and coverage CI jobs.
- Remove the legacy `token-hash:v1` marker from production persistence
  validation and align persistence tests on the current `token-hash:v2`
  format.

## 0.1.10

- Keep the smoke-test secure example config command as a single Meson
  expression for compatibility with the Meson version shipped by Ubuntu 24.04.

## 0.1.9

- Normalize repository shell scripts to LF and enforce shell-script line endings
  for WSL builds.
- Move permission-sensitive smoke-test fixtures into a Linux temporary
  directory so `/mnt/c` metadata does not block Unix mode checks.

## 0.1.8

- Run source-gate shell scripts through `sh` in Meson tests so WSL `/mnt/c`
  builds do not depend on executable bits or direct shebang execution.

## 0.1.7

- Suppressed Clang 22's `-Wc2y-extensions` diagnostic so Catch2 `__COUNTER__`
  test-registration macros do not fail `-Werror` builds.

## 0.1.6

- Added Linux and WSL build wrapper scripts for repeatable Clang 22 Meson builds.
- Added smoke coverage for the Linux build wrapper help and dry-run paths.
- Documented the WSL build workflow and Catch2 wrap fallback behavior.

## 0.1.5

- Promoted the client-server runtime API to production-named headers, source files, and entry points.
- Removed the old MVP-named client-server public symbols from the primary API surface.
- Added BDD coverage for the production-named client-server start and flow APIs.

## 0.1.4

- Replaced client-server registration, password login, and device update pipe bodies with parsed Matrix JSON request bodies.
- Added a single-request HTTP/1.1 adapter for the client-server facade with bearer-token extraction and exact body-length enforcement.
- Added fail-closed Matrix `M_BAD_JSON` coverage for malformed and incomplete client-server auth requests.
- Documented the remaining client-server production-readiness gap: the socket accept/read/write loop still needs to call the HTTP adapter.

## 0.1.3

- Replaced local homeserver password and access-token hashing with LibSodium-backed Argon2id/CSPRNG/generic-hash handling.
- Replaced the custom media SHA-256 implementation with LibSodium generic hashing for deduplication digests.
- Added Linux, OpenRC, BSD rc.d, and container packaging skeletons with production hardening defaults.
- Added release-readiness and security-review documentation plus a CI release metadata gate.
- Added BDD coverage for hardened local auth hash and token behavior.

## 0.1.2

- Preserved media repository and admin HTTP status codes through local homeserver routes.
- Added regression coverage for unauthenticated media uploads, admin media misses, quarantined downloads, remote media rejection, and zero-reference blob reupload.
- Documented the media repository status, digest, audit, and schema migration behavior.

## 0.1.1

- Added a Linux/BSD developer environment setup script with dry-run, check-only, package-manager override, and Meson build-directory configuration support.
- Documented the developer environment workflow and linked it from the README.
- Added smoke coverage for Linux, FreeBSD, OpenBSD, and NetBSD setup command planning.

## 0.1.0

- Initial secure bootstrap implementation with Meson build, configuration validation, runtime summaries, and security-focused test scaffolding.
