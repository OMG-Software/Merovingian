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
- **fix(auth): include `soft_logout: true` in 401 responses for expired access tokens (spec §5.7.2):** when an access token is found-but-expired the server now returns `{"errcode":"M_UNKNOWN_TOKEN","error":"unauthenticated","soft_logout":true}` so Matrix clients use their refresh token rather than performing a full session logout. Revoked tokens continue to return a plain 401 without `soft_logout`, preserving hard-logout semantics for explicit revocations.

### Changed
- **chore(release): beta milestone — promote from pre-beta (0.8.x) to beta phase (0.9.0):** version number advanced to 0.9.0 per the versioning scheme phase markers. No functional changes; this commit updates all version strings across `meson.build`, source files, packaging metadata, and build scripts.
- **docs: update README to reflect beta status:** banner note and Project Status section updated from pre-beta/in-development language to beta; pre-beta changelog history archived to `CHANGELOG-pre-beta.md`.
