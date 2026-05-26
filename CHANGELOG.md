# Changelog

## 0.4.18

- Make synchronous outbound federation membership requests fail closed when the
  runtime signing key is not already initialized, instead of performing hidden
  signing-key setup inside the generic outbound helper.
- Refuse to start the federation dispatch worker when the persisted signing key
  cannot be hydrated into a valid Ed25519 secret, instead of masking the fault
  with a fallback `key_id`.
- Set `CURLOPT_PATH_AS_IS` for outbound HTTPS requests and add integration
  coverage that captures the raw TLS request line. This protects
  signature-sensitive federation requests such as `make_join` from path
  normalization drifting the on-wire URI away from the URI that was signed.
- Split the old `vertical_slice.hpp` umbrella into implementation-matched
  homeserver headers (`runtime`, `auth_service`, `room_service`,
  `media_service`, `local_http_router`) and rename the old demo helper to
  `local_smoke_flow` so the interface names match what the code actually does.

## 0.4.17

- Fix null-byte truncation of the Ed25519 signing key secret on database reload.
  The secret is now stored as unpadded standard base64 text instead of raw bytes.
  Raw Ed25519 secret keys (64 bytes) frequently contain embedded null bytes; the
  previous approach used `sqlite3_column_text` / libpq's null-terminated string
  APIs to load the value, silently truncating the key and causing
  `make_federation_signature` to return an empty signature string, which Synapse
  rejected with `401 BadSignatureError` on every outbound `make_join` request.

## 0.4.16

- Persist the server Ed25519 signing key secret across restarts. Previously
  every restart generated a new keypair (UPSERT overwrote the public key, secret
  lived in-memory only), so Synapse's cached public key became invalid and all
  outbound federation requests were rejected with 401, opening the circuit
  breaker. The secret key is now stored in `server_signing_keys.secret_key` and
  restored on startup so the server's identity is stable across restarts.

## 0.4.14

- Percent-encode outbound federation membership path components (`make_join`,
  `send_join`, `invite`, `backfill`) before signing and sending, so Synapse no
  longer rejects remote invites with `401 Unauthorized` due to a signed URI
  mismatch.
- Add `query_params::encode_path_component()` for safe percent-encoding of
  Matrix path segments.

## 0.4.13

- Percent-encoded outbound federation membership path components before signing
  and sending `make_join`, `send_join`, `invite`, and `backfill` requests, so
  Synapse no longer rejects remote invites with `401 Unauthorized` due to a
  signed URI mismatch.
- Rewrote `README.md` so it now opens with an explicit active-development /
  not-ready warning, explains Merovingian's security-first design goals, and
  links directly to deployment/runtime and development onboarding docs.
- Persisted stripped state from inbound federation invites and exposed it via
  `rooms.invite.*.invite_state.events` in `/sync`, so DM invites initiated from
  Synapse carry the room metadata Element expects.
- Added durable invite-state storage to the initial schema, plus regression
  coverage for the invite-sync path and schema bootstrap chain.

## 0.4.12

- Bumped project, executable, and package metadata versions to `0.4.12` so a
  fresh PR merge to `main` can publish new rolling `latest` artifacts.

## 0.4.11

- Signed Matrix events over the full canonical event payload instead of a
  redacted copy, so Synapse can verify room-state signatures during federation
  joins.
- Added `room_version` and `origin` to federated `send_join` responses, and
  `room_version` to other `send_*` membership responses, matching the documented
  federation response shape.
- Flushed low-severity console and file logs every 1 second or every 100
  messages, whichever comes first, so debug diagnostics appear promptly even
  during quiet periods.
- Logged `Starting merovingian-server <version>` during normal startup so operators can
  identify the running binary version from startup logs, and removed the
  misleading "bootstrap server" wording from normal help/startup surfaces.
- Fixed federation membership path parsing to percent-decode invite room and
  event IDs before validation, so Synapse v2 federation invites no longer fail
  on encoded path segments.
- Documented reverse-proxy deployment as the preferred operating model, and
  updated Apache httpd and nginx examples to match that recommendation.
- Updated Apache httpd and nginx reverse-proxy examples to split client traffic
  from federation/key traffic on `443`, and to show the matching
  `/.well-known/matrix/server` delegation.
- Bumped project, executable, and package metadata versions to `0.4.11`.

## 0.4.10

- Fixed inbound federation `send_join` state handling so accepted remote joins
  update both durable membership rows and the runtime room member list. Local
  messages in shared rooms are now queued for the remote member's homeserver.
- Fixed inbound federation invites to validate the target local user, sign the
  invite event with the local server key, persist the invite membership, and
  wake `/sync` so clients can see and accept the invite.
- Added outbound invite delivery for `POST /_matrix/client/v3/createRoom`
  `invite` entries that target remote Matrix users.
- Fixed outbound `createRoom` invite dispatch to assign a federation
  transaction id before queueing, so the dispatch worker accepts the invite
  transaction for delivery.
- Fixed release packaging helper scripts to build `0.4.10` artifacts after
  the branch version bump.
- Fixed join-after-invite membership transitions so successful local or remote
  joins update existing durable invite rows to `join`.
- Fixed remote-room joins to persist the remote room and hydrate joined members
  from the `send_join` state response, so messages sent after accepting a
  Synapse invite have remote destinations to deliver to.
- Bumped project, executable, and package metadata versions to `0.4.10`.

## 0.4.9

- Added live Synapse federation integration tests against matrix.ping.me.uk
  and pong.ping.me.uk. Seven test scenarios exercise real TLS, DNS, and
  HTTPS against a production Synapse server: key fetch, version endpoint,
  profile query, well-known discovery, full discovery + key verification
  pipeline, and inbound probes of Merovingian's key and well-known
  endpoints.
- Moved the live Synapse federation suite behind the new Meson option
  `-Dbuild_live_tests=true` so default integration builds remain deterministic
  and do not depend on external homeserver availability. The live scenarios
  still SKIP when the remote server is unreachable.
- Fixed live federation DNS pinning to extract the actual IPv4/IPv6 address
  payload from each resolved `sockaddr` before passing it to `inet_ntop`.
- Locked in the federation auth compatibility behavior that returns `502`
  rather than `401` for malformed or unverifiable federation signatures, so
  Synapse does not propagate those failures to clients as logout-triggering
  `401 Unauthorized` responses.

## 0.4.8

- Replaced the single-threaded listener model with a bounded `ThreadPool`
  (`merovingian/net/thread_pool.hpp`). Listener threads now run thin accept
  loops that submit accepted connections to a pool of `std::jthread` workers,
  enabling concurrent request processing instead of one-at-a-time dispatch.
- Implemented two-phase sync dispatch: `sync_json()` returns a `DispatchResult`
  tagged union. When the `/sync` handler needs to long-poll, it returns
  `needs_wait` with `SyncWaitParams` instead of holding the `runtime_lock`.
  `dispatch_local_http_request()` then releases the lock, waits on the
  `SyncNotifier`, reacquires the lock, and calls the handler again with
  `can_wait=false`. This eliminates the root cause of Synapse CancelledError
  on federation profile queries caused by nginx/reverse-proxy timeouts.
- Removed the `dispatch_lock` parameter from all handler signatures. Handler
  functions no longer need to be aware of lock management — the two-phase
  dispatch in `dispatch_local_http_request()` handles it transparently.
- Made `HttpServeStats` counters `std::atomic<std::uint64_t>` so they no
  longer need `runtime_lock` protection. Added move operations to support
  return-by-value from `serve_until_shutdown()`.
- Added `SocketHandle::release()` to transfer fd ownership into pool workers
  without premature close.

## 0.4.7

- Fixed `runtime_lock` being held during `/sync` long-poll wait, which blocked
  federation request dispatch for up to 30 seconds and caused Synapse
  CancelledError on profile queries and key claims. The lock is now released
  before the condition_variable wait and reacquired after, allowing federation
  and other listeners to dispatch concurrently with sync long-polls.
- Extended `SyncNotifier` to track both `stream_ordering` (timeline events) and
  `sync_stream_id` (to-device, presence, device_lists, account_data) so that
  timeline events from local actions wake parked `/sync` requests immediately.
- Added missing `sync_notifier->publish()` calls for all local event paths:
  room leave, client-side typing and read receipts, federation send_join
  membership acceptance, inbound typing and receipt EDUs, device deletion,
  and device key uploads. Each publishes with the correct stream counters so
  `/sync` long-polls return promptly instead of waiting for the full timeout.
- Added `record_device_list_change` calls for device deletion and device key
  upload so that other users sharing a room with the affected user see the
  device list update in their `/sync` stream.
- Fixed `stream_ordering=0` bug in the federation `membership_acceptor`:
  inbound `send_join` events now advance `next_stream_ordering` before being
  stored, so they appear in the `/sync` timeline instead of being silently
  skipped.
- Fixed `next_sync_stream_id` not advancing on membership changes (room
  creation, local join, remote join, leave): the sync stream counter is now
  incremented before the publish call so `/sync` actually wakes on membership
  changes rather than timing out.

## 0.4.6

- Fixed `PUT /_matrix/federation/v1/send/{txnId}` response body returning
  plain-text diagnostic strings instead of the Matrix-required `{"pdus":{}}`
  JSON, which caused Synapse to fail with JSONDecodeError on transaction
  responses. The 400 rejection now also returns proper JSON with `M_BAD_JSON`.

## 0.4.5

## 0.4.4

- Wired inbound EDU sink for all five EDU types (typing, receipt, presence,
  direct_to_device, device_list_update): federation EDUs received via
  `PUT /_matrix/federation/v1/send/{txnId}` are now classified, validated,
  and dispatched to the appropriate runtime handler. Typing and receipts
  update in-memory state for `/sync`; presence, to-device, and device list
  changes are persisted to the database and publish sync notifications.
- Wired outbound membership into `join_room` for remote rooms: when a local
  user joins a room that is not in the local database, the server now
  performs a synchronous `make_join` → sign → `send_join` flow with the
  remote homeserver, persists the returned state events and auth chain, and
  creates the local room membership record.
- Removed the `device_list_update` routing exclusion from the key API router
  and wired `record_device_list_change` in the device update handler so that
  all local users who share a room with the updated user receive a device
  list change notification in their `/sync` stream.
- Added outbound EDU dispatch for typing notifications and read receipts:
  when a local user sets their typing state or posts a read marker, the
  server now federates the corresponding `m.typing` or `m.receipt` EDU to
  all remote servers that have members in the room.
- Added `PUT /_matrix/client/v3/presence/{userId}/status` route that persists
  the presence state via `set_presence` and publishes a sync notification.
- Added `InboundTypingUser` and `InboundReceipt` structs to
  `HomeserverRuntime` for transient EDU state used by `/sync`.

## 0.4.3

- Fixed inbound PDU sync visibility: federation events received via
  `PUT /_matrix/federation/v1/send/{txnId}` now have `stream_ordering` assigned
  from `next_stream_ordering` and trigger a `SyncNotifier::publish` after
  persistence, so remote messages appear in client `/sync` responses.
- Wired outbound PDU dispatch from local events: `send_event` now enumerates
  remote server names from room members, builds federation transaction bodies
  (`{"pdus":[...],"edus":[]}`), and enqueues `OutboundTransaction` items in the
  `DispatchWorker` for each remote destination. The `DispatchWorker` (previously
  implemented but never connected) is now created and started during federation
  callback wiring.
- Made `wire_federation_callbacks` a public API so that outbound dispatch can
  be lazily triggered from the client-server event-sending path, not just from
  inbound federation requests.

## 0.4.2

- Fixed federation invite path parsing: `/_matrix/federation/v2/invite/{roomId}/{eventId}`
  and `/_matrix/federation/v1/invite/{roomId}/{eventId}` routes no longer emit a
  spurious `membership_path.rejected` diagnostic. The invite endpoint is now handled
  natively by `parse_membership_path` instead of falling through to a `send_join`
  hack with manual fallback parsing.
- Added `im.nheko.summary` room summary endpoints for Nheko compatibility:
  `GET /_matrix/client/unstable/im.nheko.summary/summary/{roomId}` and
  `GET /_matrix/client/unstable/im.nheko.summary/rooms/{roomId}/summary` now return
  room membership summaries (heroes, joined count, invited count) instead of 404.

## 0.4.1

- Fixed `POST /join/{roomId}` returning 500 when the user is already a member
  in the persistent store but absent from the in-memory `LocalRoom::members`
  list (stale in-memory state after a restart or failed prior join attempt).
  `store_membership` now returns a `MembershipStoreResult` tri-state
  (`stored`, `already_exists`, `error`) so callers can distinguish a genuine
  backend failure from a harmless duplicate; the room service treats
  `already_exists` as an idempotent success and re-syncs the in-memory member
  list.

## 0.4.0

- Added the client-server `POST /_matrix/client/v3/rooms/{roomId}/leave` route
  with membership enforcement and persistent store update.
- Added the client-server `POST /_matrix/client/v3/rooms/{roomId}/read_markers`
  route (accepted, no-op; persistence is future work).
- Added structured `log_diagnostic` debug logging to six previously-silent
  modules: federation discovery/signature/trust-policy, federation dispatch
  worker, HTTP outbound client, media security, platform hardening self-check,
  and homeserver runtime startup.
- Fixed missing `platform_lib` linkage in `merovingian-db-migrate`, resolving
  undefined-reference linker errors from `hardening_self_check` symbols pulled
  in transitively through `observability_lib`.
- Bumped project, executable, and package metadata versions to `0.4.0`.

## 0.3.6

- Added structured `log_diagnostic` debug logging to six previously-silent
  modules: `federation/security` (discovery, signature, and trust-policy
  rejections), `federation/dispatch_worker` (enqueue rejections, delivery,
  retry backoff, circuit-open re-queue, and max-retries drop),
  `http/outbound_client` (all failure paths, redirect-rejected, and success),
  `media/security` (upload, decoder, remote-fetch, and admin-quarantine policy
  decisions with MIME type and size context),
  `platform/hardening_self_check` (non-enabled checks and overall startup
  summary), and `homeserver/runtime` (startup stage milestones and all
  rejection paths).
- Added the client-server `POST /_matrix/client/v3/rooms/{roomId}/leave` route.
  Returns 404 `M_NOT_FOUND` for unknown rooms, 403 `M_FORBIDDEN` when the
  authenticated user is not a current member, and 200 on success. Membership is
  updated to `leave` in the persistent store via the new `update_membership`
  helper; the user is removed from the in-memory room member list.
- Added the client-server `POST /_matrix/client/v3/rooms/{roomId}/read_markers`
  route. Currently a no-op that returns 200 `{}` (read-marker persistence is
  future work).
- Added the client-server `PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`
  route. Requests where the path `userId` does not match the authenticated
  user return 403 `M_FORBIDDEN`; otherwise the request is accepted and the
  transient typing state is not persisted (typing is an EDU surface).
- Added the client-server `GET /_matrix/client/v3/rooms/{roomId}/messages`
  route. The handler enforces room membership (403 for non-members),
  paginates events by `stream_ordering` with optional `from`, `dir` (`b`
  default / `f`), and `limit` (default 10, capped at 100), and returns the
  Matrix-shaped `{chunk, start, end, state}` response.
- Bumped project, executable, and package metadata versions to `0.3.6`.

## 0.3.5

- Added the inbound federation event-graph routes:
  `GET /_matrix/federation/v1/event/{eventId}`,
  `GET /_matrix/federation/v1/state/{roomId}`,
  `GET /_matrix/federation/v1/state_ids/{roomId}`, and
  `POST /_matrix/federation/v1/get_missing_events/{roomId}`. The new
  `event_query` module builds the canonical-JSON responses from the
  persistent event and state stores; `event/{eventId}` resolves a single PDU
  by ID, `state`/`state_ids` return the room's current state (historical
  state-at-event reconstruction remains future work), and
  `get_missing_events` returns events filtered by `min_depth` and capped by
  `limit`. Each route is dispatched through an optional runtime hook and
  responds 501 Not Implemented when the hook is unset.
- Bumped project, executable, and package metadata versions to `0.3.5`.

## 0.3.4

- Added the inbound federation `GET /_matrix/federation/v1/query/profile` route.
  A signed request is dispatched through the `profile_query_provider` runtime
  hook, which reads the local user's `displayname`/`avatar_url` from the
  persistent store; the optional `field` parameter restricts the response and
  an unknown user returns 404 `M_NOT_FOUND`.
- Added the inbound federation E2EE key routes:
  `POST /_matrix/federation/v1/user/keys/query`,
  `POST /_matrix/federation/v1/user/keys/claim`, and
  `GET /_matrix/federation/v1/user/devices/{userId}`. The new `key_query`
  module builds the canonical-JSON responses from the device-key,
  one-time-key, and cross-signing-key stores; `user/keys/claim` consumes the
  claimed one-time keys. Each route is dispatched through an optional runtime
  hook and responds 501 Not Implemented when the hook is unset.
- Bumped project, executable, and package metadata versions to `0.3.4`.

## 0.3.3

- Added `parse_x_matrix_authorization_header` to extract `origin`, `destination`,
  `key_id`, and `sig` fields from inbound `X-Matrix` Authorization headers, with
  unit coverage for valid, minimal, malformed, and wrong-scheme inputs.
- Added TLS-bound origin validation: inbound federation requests where
  `tls_peer_server_name` differs from the `X-Matrix` `origin` are rejected with
  403 before any further processing.
- Wired all seven `FederationRuntimeState` callbacks lazily on the first inbound
  federation request: `pdu_sink` persists PDUs through the persistent store;
  `state_conflict_resolver` merges conflicting state via `apply_state_resolution_v2`;
  `membership_template_provider` and `membership_acceptor` serve `make_join`,
  `make_leave`, `make_knock`, `send_join`, `send_leave`, `send_knock`; `invite_handler`
  echoes back the invite JSON; `backfill_provider` serves PDUs from durable event rows;
  `remote_key_resolver` uses `make_persistent_remote_key_resolver` for discovered and
  rotation-triggered remote key fetch, verify, and cache.
- Extended PostgreSQL restart-survival integration tests to cover users, access
  tokens, rooms, memberships, events, account data, policy rules, federation
  destinations, federation transactions, local media, and remote media across a
  close/reopen cycle.
- Exposed `make_system_server_discovery_network()` as a public factory and added
  `std::shared_ptr<OutboundClient>` and `std::shared_ptr<ServerDiscoveryNetwork>`
  fields to `HomeserverRuntime` so the remote-key resolver can be constructed at
  startup without lifetime issues.
- Fixed missing `<memory>` include in `server_discovery.hpp` required by the
  `make_system_server_discovery_network` declaration.
- Replaced the federation request-signing scheme with the Matrix-spec X-Matrix
  scheme so Merovingian can interoperate with other homeservers. The signed
  payload is now the canonical JSON object `{content?, destination, method,
  origin, uri}` — `content` is the request body parsed as a JSON object and is
  omitted for body-less requests; no non-standard `origin_server_ts` is signed.
  Requests are signed with the server's real Ed25519 secret key and verified
  against the remote's published `/_matrix/key/v2/server` public key.
- Removed the prior shared-secret `verify_token` key derivation, which signed
  and verified with a symmetric secret and therefore could never interoperate
  with a real Matrix homeserver. `make_federation_signature` now takes the raw
  Ed25519 secret key; `verify_signed_federation_request` verifies against the
  remote's public key; `SignedFederationRequest` carries `destination` instead
  of `origin_server_ts`; the X-Matrix Authorization header now emits
  `destination`.
- Bumped project, executable, and package metadata versions to `0.3.3`.

## 0.3.2

- Fixed client-server room joins for browser-encoded room IDs such as
  `!room%3Aserver`: Matrix path components are decoded before local room
  lookup, so join-by-id no longer rejects existing rooms as unknown.
- Documented the operator debug logging workflow for diagnosing failed room
  joins without logging access tokens, passwords, Matrix event bodies, media
  payloads, or signatures.
- Bumped project, executable, and package metadata versions to `0.3.1`.

## 0.3.1

- Added redaction-aware debug diagnostics for HTTP request ingress/egress,
  client-server auth and route decisions, local room join/send/state handling,
  event authorization rejections, persistent-store writes, federation ingress,
  and outbound federation membership transaction composition.
- Added diagnostic log sanitization for sensitive field names and Matrix request
  targets containing token-like query parameters.
- Added `merovingian-server --debug` and `--log-file <path>` so operators can
  enable console and file diagnostics during room-join triage.

## 0.3.0

- Added Matrix UI-Interactive Authentication for `POST /register`: when the
  request body omits the `auth` field the server returns 401 with the
  `m.login.registration_token` flow, a `params` object, and a `session` token
  rather than a flat 403 error.
- Added `POST /_matrix/client/v3/account/password` endpoint: authenticated users
  can change their password; the new value is validated, hashed with Argon2id,
  and written through to both the in-memory runtime and the persistent store.
- Added `PUT /_matrix/client/v3/profile/{userId}/displayname` and
  `PUT /_matrix/client/v3/profile/{userId}/avatar_url` endpoints with
  cross-user 403 protection and JSON-body validation.
- Moved `GET /_matrix/client/v3/profile/{userId}` before the access-token gate
  so it is unauthenticated per the Matrix spec; returns 404 for unknown users.
- Fixed `GET /_matrix/client/v3/profile/{userId}/{keyName}` (`getProfileField`)
  to return only the requested field instead of the whole profile object; an
  unset or unknown field now returns 404 M_NOT_FOUND.
- Extended the client-server v1.18 Complement-style conformance fixture with
  profile negative cases (unknown-user 404, cross-user PUT 403), unknown-room
  state GET (403), and password-change coverage (unauthenticated 401,
  weak-password 400, valid change 200).
- Bumped project, executable, and package metadata versions to `0.3.0`.

## 0.2.17

- Added durable media blob storage, policy-rule persistence, and media-blob
  hydration for SQLite/PostgreSQL-backed runtime restarts.
- Added hardened media processing boundaries for uploads and remote media
  ingestion: sandbox requirement, AV scanner boundary, decoder/decompression
  limits, thumbnail metadata generation, and fail-closed tests.
- Added a configurable remote media fetch boundary and repository-level remote
  media ingest flow while keeping remote downloads disabled unless explicitly
  enabled by configuration.
- Bumped project, executable, and package metadata versions to `0.2.17`.

## 0.2.16

- Added a beta Matrix v1.18 Complement-style fixture covering authentication,
  devices, rooms, sync, filter/account-data, capabilities, push rules, media
  config/upload/download, reports, and E2EE key APIs through the client-server
  adapter, including rejected unauthenticated, malformed, stale-token,
  cross-user, and missing-resource endpoint cases.
- Implemented refresh-token issuance/rotation, global logout, single-device
  fetch/delete, global/device refresh-token revocation, durable device
  display-name updates, spec-shaped room
  `PUT /send/{eventType}/{txnId}` and `PUT /state/{eventType}/{stateKey}`
  aliases, and client-server media upload/download adapter coverage.
- Persisted refresh-token rows and added persistent-store helpers for revoking
  all user/device access tokens and mutating device metadata.
- `GET /_matrix/media/v3/config` now reports `m.upload.size` from
  `security.media.max_upload_size` instead of a hard-coded 100 MiB value.
- Spec-shaped room send/state aliases now reject malformed or non-object JSON
  event content instead of silently wrapping it as `null`.
- Login now only returns refresh-token fields when the Matrix login body sets
  `refresh_token: true`, and event reports follow Matrix v1.18 by accepting an
  optional `reason` and ignoring the removed legacy `score` field.
- `/keys/query` and `/keys/claim` now honor their Matrix request-body maps
  instead of returning or claiming only the caller's current device keys.
- Added a generated Matrix v1.18 Client-Server API reference document from the
  official OpenAPI description, plus a deterministic regeneration script.

## 0.2.15

- Generalised the MSC2965 OIDC discovery handling: the entire
  `org.matrix.msc2965` namespace (`auth_metadata`, `auth_issuer`) now returns
  404 M_UNRECOGNIZED before the access-token gate. `auth_issuer` was still
  producing a misleading 401.
- Added `GET /_matrix/client/v3/voip/turnServer` returning an empty object.
  No TURN server is configured; an empty 200 lets clients disable VoIP
  gracefully instead of treating a 404 as an error.
- Added `POST /_matrix/client/v3/join/{roomIdOrAlias}` which joins by room ID
  or alias. It delegates to the same local join handler as
  `/rooms/{roomId}/join` by rewriting the request target.
- Added `PUT` and `GET /_matrix/client/v3/user/{userId}/account_data/{type}`
  for global (non-room) account data. Cinny stores `m.direct` (the
  direct-message room list) here immediately after creating a room.
  Room-scoped account data is not yet implemented.

## 0.2.14

- Raised `ClientApiLimits::max_body_bytes` from 4 KiB to 64 KiB so real E2EE
  key uploads (device keys + many one-time keys) are no longer rejected with
  413 M_TOO_LARGE.
- Added `GET /_matrix/client/v3/profile/{userId}` returning an empty stub
  profile (`displayname` / `avatar_url`). Cinny fetches this immediately after
  login to populate the user-info header; the previous 404 left it blank.
- Added `GET /_matrix/media/v3/config` returning `{"m.upload.size": 104857600}`
  (100 MiB). Cinny fetches this to know the maximum attachment size.
- `GET /_matrix/client/unstable/org.matrix.msc2965/auth_metadata` now returns
  404 M_UNRECOGNIZED before the access-token gate. Cinny probes this for OIDC
  support; the previous 401 could mislead clients into thinking OIDC was
  configured but broken.

## 0.2.13

- Added `POST /_matrix/client/v3/user/{userId}/filter` to store a sync filter and
  return a `filter_id`. Added `GET /_matrix/client/v3/user/{userId}/filter/{filterId}`
  to retrieve a previously stored filter. Cinny posts a filter immediately after
  login and uses the returned `filter_id` in all `/sync` requests.
- Added `--disable-dependency-tracking` to the curl packagefile configure options
  so automake's `depcomp` bootstrap no longer fails on NTFS-backed filesystems
  (WSL builds under `/mnt/c/`).
- Added `scripts/build-wsl.sh`: a dedicated WSL build wrapper that defaults to
  `build-wsl`, auto-detects and wipes stale curl subproject directories (those
  configured without `--disable-dependency-tracking`), auto-reextracts stale
  `subprojects/curl-<version>` packagefile copies, and accepts `--clean` for a
  full rebuild without reusing stale extracted curl sources. Updated
  `scripts/wsl-setup.sh`, `scripts/build-wsl.ps1`, and `build-wsl.cmd` to point
  at the new script, and removed the hardcoded `Ubuntu-24.04` launcher
  dependency so the default WSL distro works out of the box. The WSL wrapper
  now stages an executable `make` shim under the Linux filesystem so Meson's
  `external_project` helper can invoke it even when the repo lives on `/mnt/c`,
  and rewrites that shim with LF line endings so the shebang stays executable.
- Replaced all `static_cast<void>(expr)` and `(void)expr` return-value discards
  with `std::ignore = expr` across 18 files for consistent `[[nodiscard]]`/
  `warn_unused_result` suppression.

## 0.2.11

- Added `GET /_matrix/client/v3/capabilities` stub returning server capability
  flags. Cinny and Element Web require this before opening a sync connection.
- Added `GET /_matrix/client/v3/pushrules/` stub returning an empty global
  ruleset. Cinny fetches this immediately after login; a 404 caused the
  "Connection lost" error before sync was established.

## 0.2.10

- Added `GET /.well-known/matrix/client` endpoint so browser-based Matrix
  clients (Cinny, Element Web) can discover the homeserver base URL without
  requiring a separate static file served by the reverse proxy.
- Fixed `OPTIONS` preflight requests returning `401 M_UNKNOWN_TOKEN`. Browser
  clients send an OPTIONS preflight before every cross-origin POST; the
  access-token gate was rejecting them before any route handler ran, causing
  all login and register attempts from web clients to fail silently.

## 0.2.9

- Fixed `login_local_user()` returning HTTP `400` instead of `403` for unknown
  user, bad credentials, and policy-denied (locked/suspended) accounts.
  The Matrix spec (§5.7.2) requires `403 M_FORBIDDEN` for all credential
  failures; the default `make_operation_result` fallback of `400` was incorrect.
  Added BDD scenarios covering both the unknown-user and wrong-password cases.

## 0.2.8

- Fixed malformed SQL in `insert_device_statement` and `persist_token_hash_statement`
  (`src/auth/client_server_api.cpp`): column lists and value tuples were missing
  parentheses, causing every login and registration request to fail at the database
  layer. Added a BDD unit test that asserts all INSERT statements in the login and
  register boundary plans use valid `INSERT INTO table (cols) VALUES ($1, …)` syntax.

## 0.2.6

- `merovingian-server` now searches `$sysconfdir/merovingian/merovingian.conf`
  automatically when started with no `--config` flag. The sysconfdir is baked in
  at build time via Meson's `get_option('sysconfdir')` so packages install to
  `/etc` and FreeBSD packages install to `/usr/local/etc` without any runtime
  detection.
- `.deb`, `.rpm`, and FreeBSD `.pkg` post-install scripts now generate
  `/etc/merovingian/registration-token` (or `/usr/local/etc/…` on FreeBSD) using
  `openssl rand -base64 48` if the file does not already exist. The file is owned
  `root:merovingian` mode `0640` so the server process can read it but it is not
  world-readable. Existing tokens are never overwritten on upgrade.

## 0.2.5

- Changed the default and example internal federation listener from
  `127.0.0.1:8448` to `127.0.0.1:8009` so Apache or another reverse proxy can
  own the public Matrix federation port `8448`.
- Added Apache httpd and nginx reverse-proxy examples for the recommended
  loopback listener deployment.
- Added BDD coverage proving runtime listener planning preserves a configured
  custom federation bind address.
- Bumped project, executable, and package metadata versions to `0.2.5`.

## 0.2.4

- Added section-level explanatory comments to
  `config/merovingian.conf.example` covering server identity, listener
  exposure, database secret handling, registration, encryption, federation,
  media safety, and logging redaction.
- Added tooling coverage to keep the example config's operator guidance in
  place.
- Bumped project, executable, and package metadata versions to `0.2.4`.

## 0.2.3

- Added an Alpine/musl static Linux fallback tarball to `.github/workflows/packages.yml`
  for older Linux distributions that cannot easily consume the `.deb` or `.rpm`.
- Added `scripts/build-static-linux.sh`, which builds `merovingian-server` and
  `merovingian-db-migrate` as `-static-pie` binaries and rejects artifacts that
  still contain a dynamic interpreter.
- Fixed `.github/workflows/packages.yml` so the rolling `latest` GitHub release
  is looked up and deleted with explicit `--repo "${{ github.repository }}"`
  scoping before it is recreated from `main`.
- Added tooling coverage for `.github/workflows/packages.yml` so CI rejects
  repo-implicit `gh release` usage in the artifact-only rolling release job.
- Aligned Debian, RPM, and FreeBSD package metadata with version `0.2.3`.
- Aligned `merovingian-server`, `merovingian-db-migrate`, and the Meson project
  version to `0.2.3`.
- Updated the release-process and progress-tracker docs for the rolling
  `latest` publication path.

## 0.2.2

- Switch `.deb` build from Alpine (fully static) to Ubuntu with dynamic OS library linking.
- Declared `libssl3`, `libsodium23`, and `libpq5` as runtime `Depends` in the `.deb` package so
  distro security updates patch these libraries without rebuilding Merovingian.
- App-level dependencies (SQLite, curl, yyjson) remain statically linked via source-pinned Meson wraps.
- Added `CODE_OF_CONDUCT.md` adapted from Contributor Covenant v2.1.
- Fixed intermittent 403 in rate-limit cross-user isolation test: `registration_token_file()` now
  creates a process-unique filename (random salt + atomic counter) so parallel `meson test` jobs
  no longer truncate each other's token file during concurrent `std::ofstream` construction.

## 0.2.1

- Added distro packaging: `.deb` (Debian/Ubuntu), `.rpm` (Fedora), and `.pkg` (FreeBSD).
- New scripts: `scripts/build-deb.sh`, `scripts/build-rpm.sh`, `scripts/build-freebsd-pkg.sh`.
- New packaging support files: `packaging/deb/postinst`, `packaging/deb/prerm`, `packaging/deb/conffiles`,
  `packaging/rpm/merovingian.spec`, `packaging/freebsd/+MANIFEST`.
- New CI workflow `.github/workflows/packages.yml` produces installable packages on every push to
  `main`, `feature/**`, `codex/**`, and `alpha-release`.
- All distribution binaries statically link application dependencies (libsodium, OpenSSL, libpq,
  libcurl, sqlite3). The `.deb` is built on Alpine (musl) with `-static-pie` — fully static with
  ASLR. The `.rpm` and FreeBSD `.pkg` use `--prefer-static` with `-pie` (dynamic libc, static app
  libs).
- `meson.build`: removed `b_pie=true` and ELF-dynamic-only link flags (`-pie`, `-Wl,-z,relro/now`);
  retained `-fPIE` (compile) and `-Wl,-z,noexecstack` (kernel-enforced on static and dynamic ELF);
  PIE link flag supplied per-platform via `cpp_link_args` in each build script.
- Fedora and FreeBSD builds no longer pass `--prefer-static` to meson; system security
  libraries (libpq, libsodium, openssl) link dynamically so they receive OS security updates,
  while app-level dependencies (SQLite, curl, yyjson) remain statically linked via wraps.
  The `--prefer-static` flag caused `libpq.pc`'s `Libs.private` transitive deps (pgcommon,
  pgport, gssapi, ldap) to be added to the link, but these have no static variants on
  Fedora or FreeBSD. The Alpine deb retains full static linking via `-static-pie`.
- CI fixes: `libpq.a` static link now resolves `pg_encoding_to_char` via `libpgcommon_shlib.a`
  (Alpine's frontend pgcommon variant); RPM build uses `tar` instead of `git archive` to avoid
  `GIT_DISCOVERY_ACROSS_FILESYSTEM` failures in Docker containers; FreeBSD build uses
  `--wrap-mode=default` so system curl is preferred while yyjson can still fall back to its wrap;
  sqlite3 subproject compiled with `warning_level=0`/`werror=false` to suppress Fedora RPM
  toolchain warnings in third-party C code; fixed redundant `std::move` from `const` optional
  in `server_discovery.cpp` (GCC 16 `-Wredundant-move`); added `git` to FreeBSD CI prepare
  step so the yyjson git wrap can clone the source.


## 0.2.0

- Bump to alpha release version.

## 0.1.65

- Added `docs/security-code-audit-alpha.md`, a structured alpha code-audit
  report covering scope, threat model, findings, test gaps, and remediation
  priorities for the current repository state.
- Linked the latest code-audit report from `docs/01-progress-tracker.md`.
- Added supply-chain workflows for Gitleaks secret scanning, dependency review,
  and SPDX/CycloneDX SBOM generation.
- Added repository security-workflow contracts in
  `tests/tooling/test_security_workflows.py`, registered them in
  `tests/meson.build`, and tightened release-readiness checks for the new
  workflow/configuration files.
- Added source-pinned Meson wraps for libcurl, SQLite, Catch2, and yyjson,
  plus external-project packagefiles for native configure-based dependencies.
- Switched Linux, BSD, WSL, and setup entrypoints to
  `--wrap-mode=forcefallback` by default for source-pinned dependencies, while
  keeping OpenSSL, LibSodium, and PostgreSQL libpq resolved from
  operating-system packages with Meson fallback disabled.
- Added `scripts/tool-shims/make` so external-project wraps resolve GNU make on
  BSD hosts and forward Meson's staged `DESTDIR` as a make command-line variable
  when upstream Makefiles assign `DESTDIR=` internally.
- Updated dependency versions and build policy:
  - curl 8.12.1 to 8.20.0
  - Catch2 v3.8.1 to v3.14.0
  - OpenSSL now links dynamically from the OS package instead of the wrap
- Moved LibSodium and PostgreSQL libpq to OS-supplied dynamic library
  resolution, added package-manager dependency coverage for Linux/BSD build
  paths, and scaffolded Debian, RPM, FreeBSD, OpenBSD, and NetBSD package
  metadata that records the required dynamic library dependencies.
- Fixed curl 8.20.0 configure options and dependency naming so the fallback
  exposes `libcurl_dep`, and corrected the fallback include root so
  `<curl/curl.h>` resolves consistently on Linux and BSD.
- Disabled optional zlib and zstd support in the curl fallback so static
  fallback links do not require undeclared compression libraries.
- Disabled Catch2's upstream self-test target in fallback builds so CI only
  builds Merovingian's tests.
- Kept SQLite fallback builds static so sanitizer CI links the sanitizer runtime
  from Merovingian test executables instead of a standalone SQLite shared
  object.
- Gated `_FORTIFY_SOURCE=3` behind optimized builds so Fedora debug builds do
  not fail warnings-as-errors on glibc's "requires compiling with optimization"
  diagnostic.
- Added dependency-wrap tooling coverage for wrap pinning, OS-supplied
  OpenSSL/LibSodium/libpq resolution, make-shim `DESTDIR` forwarding, Catch2
  fallback self-test suppression, curl include-root handling, SQLite static
  fallback, package scaffold dependency metadata, and optimized-only FORTIFY
  handling.
- Added a default Meson `wrappedruntime` test setup that exposes staged
  external-project library directories through `LD_LIBRARY_PATH` for Fedora and
  other fallback-runtime test jobs.
- Raised the aggregate Catch2 unit-suite Meson timeout so fallback, coverage,
  and sanitizer CI jobs do not kill an otherwise passing suite at Meson's 30s
  default.
- Made the Phase 1 configuration validation script expose staged curl runtime
  libraries before executing `merovingian-server`, so fallback builds can find
  wrap-built runtime libraries outside Meson's test harness.
- Added a Fedora container build to CI so the Linux workflow also covers the
  Red Hat package family with `dnf`-provided dependencies.
- Fixed registration-token CRLF handling so Windows-edited token files compare
  equal after trimming carriage returns.
- Restored `pkg-config` preflight checks for the build environment, requiring
  OS-supplied OpenSSL, LibSodium, and libpq modules while avoiding
  package-module checks for dependencies still resolved through wraps.
- Enforced configured registration tokens at runtime, removed implicit
  first-public-user admin creation, and routed federation listeners through a
  federation-only dispatcher that hides admin and client compatibility routes.
- Added an explicit `merovingian-server --bootstrap-admin <localpart>
  --bootstrap-admin-password-file <path>` startup path so operators can create
  the first admin account through the persisted bootstrap API before listeners
  are bound.
- Added BDD regression coverage and documentation for token-protected
  registration, explicit admin bootstrap, and federation-only dispatch.
- Updated CI package lists and developer/dependency documentation for the
  source-pinned dependency path and OS-provided OpenSSL policy.
- Bumped project and executable versions to `0.1.65`.

## 0.1.64

- Closed the remaining two Alpha TODOs from `docs/01-progress-tracker.md`.
- Added a dedicated fuzz CI gate
  (`.github/workflows/fuzz.yml`) that builds the canonical JSON and HTTP
  transport harnesses with `-fsanitize=fuzzer,address,undefined` and runs
  each target for a bounded duration per push (120s) or scheduled run
  (900s on Sundays). Findings, crash inputs, and corpora are uploaded as
  workflow artifacts.
  - `tests/fuzz/meson.build` now applies the libFuzzer compile and link
    arguments and refuses to configure with `build_fuzz=true` when the
    compiler does not understand `-fsanitize=fuzzer`.
  - New `scripts/run-fuzz-targets.sh` wraps the build and time-bounded
    execution so the same gate can be run locally.
- Replaced placeholder hardening checks with fail-closed alpha controls
  and explicitly documented alpha-only exceptions.
  - Added `HardeningStatus::alpha_exception` and a `note` field on
    `HardeningCheck` carrying the deferred-control reason and a
    reference to `docs/hardening-alpha-exceptions.md`.
  - `HardeningSelfCheck` exposes `production_blockers()`,
    `production_blocker_count()`, `is_production_ready()`, and
    `is_alpha_ready()`. Production readiness fails closed while any
    `alpha_exception`, `disabled`, or `unknown` check remains.
  - `run_startup_hardening_self_check` tags every previously-`unknown`
    placeholder (linker hardening, RELRO, seccomp, pledge/unveil,
    capsicum, privilege drop, filesystem restrictions, core dump
    policy) as `alpha_exception` with a documented note. Compile-time
    SSP / FORTIFY / PIE probes become `alpha_exception` when the
    toolchain does not advertise the relevant macro, so every blocker
    now carries a documented note.
  - `merovingian-server` refuses to bind listeners (exit code
    `runtime_start_error`) when any hardening check reports
    `disabled`, and logs alpha-exception checks at warning level with
    a `production_ready=false alpha_ready=true` readiness summary.
  - New `docs/hardening-alpha-exceptions.md` enumerates each deferred
    control, the operator-side mitigation during alpha, and the
    beta/production retirement plan. The release-readiness script
    requires the new doc.
  - Smoke test updated to expect the new `alpha_exception` status and
    readiness summary in startup logs.
- Added tag-driven alpha prerelease publishing.
  - New GitHub Actions workflow `.github/workflows/release.yml` triggers on
    `v*-alpha*` tags, builds Linux and FreeBSD packages with the hardened
    profile, runs the normal build/test gates, generates SHA-256 checksum
    files, and publishes a GitHub prerelease.
  - The release package now carries both `merovingian-server` and
    `merovingian-db-migrate` alongside the checked config, release docs,
    packaging scaffolds, `README.md`, and `LICENSE`.
  - Added the tooling regression test
    `tests/tooling/test_release_workflow.py` and registered it in
    `tests/meson.build` so the alpha workflow contract is checked by the test
    suite.
  - `scripts/check-release-readiness.sh` now requires
    `.github/workflows/release.yml` and `docs/release-process.md` so the
    publication path cannot silently disappear.
- Added `docs/release-process.md` and updated the progress tracker plus
  security review checklist to document the alpha prerelease path and the
  production release gaps that still remain.
- Bumped project and executable versions to `0.1.64`.

## 0.1.63

- Consolidated the database schema into a single initial deploy. There
  are no live Merovingian databases to upgrade, so the assumption that
  each schema change needed a per-version migration step was wrong.
  - `current_schema_version` is now `1` and `initial_schema` is the
    only migration in the catalog. The previous v2–v7 upgrade and
    downgrade helpers are removed.
  - `core_tables` carries every column added by the retired v2–v7
    migrations (event depth/stream ordering, server-signing key
    composite primary key, federation queue replay columns, media
    metadata digest/hash, `account_data.stream_id`) plus the four
    sync-surface tables (`room_account_data`, `to_device_messages`,
    `device_list_changes`, `presence_state`). Total core table count
    is 41.
  - SQLite + PostgreSQL bootstrap statements record only the
    `initial_schema` migration row; the pre-populated v2–v6 ledger
    rows are gone.
  - Tests updated: schema-state upgrade asserts a 1-step plan ending
    at version `1`, the schema inventory counts `41` tables, and the
    persistent-homeserver flow expects a single `initial_schema`
    migration record. The "migration runner upgrades existing media
    schemas" scenario is removed; with no historic shapes to upgrade
    from, there is nothing to assert.
- Bumped project and executable versions to `0.1.63`.

## 0.1.62

- Added live PostgreSQL integration coverage and runtime/migration role
  enforcement:
  - New GitHub Actions workflow
    `.github/workflows/postgres-integration.yml` starts a PostgreSQL 16
    service, provisions a `merovingian_migration` role with DDL grants and
    a `merovingian_runtime` role with default DML privileges granted on
    tables owned by the migration role, and runs the live
    integration scenarios in
    `tests/integration/test_postgresql_persistence_flow.cpp`.
  - New BDD scenarios in the live PG test file: schema reaches
    `current_schema_version` after bootstrap, persisted rows survive a
    close/reopen cycle, and a runtime-role session is denied DDL
    (`CREATE TABLE`).
  - Added PostgreSQL role helpers `set_postgresql_role`,
    `reset_postgresql_role`, and `current_postgresql_user` on
    `merovingian::database::PostgresqlConnection`. Role names are
    validated against PostgreSQL identifier shape before being
    interpolated, so the API is safe with operator-supplied role names.
- Documented the runtime/migration role grant layout in
  `docs/database-persistence.md` and moved "runtime/migration role grants
  enforced by actual database users" out of the deferred list.
- Bumped project and executable versions to `0.1.62`.

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
