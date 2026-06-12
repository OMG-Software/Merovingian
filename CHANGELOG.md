## 0.8.0

- **feat(conformance): promote client-server endpoints from partial to spec-covered:** Added Matrix v1.18 conformance fixtures for `GET /_matrix/client/v1/auth_metadata` (MSC2965 OIDC discovery stub — 404 M_UNRECOGNIZED), `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}` and `GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` (v1.18 media thumbnail endpoints — 400/404/200 shape), and `filter_id` query parameter on `GET /sync`.

- **feat(conformance): implement `filter_id` on GET /sync:** `GET /_matrix/client/v3/sync` now resolves a `filter_id` query parameter to the stored filter object and applies it to the response. Conformance fixtures verify that a stored filter is applied when referenced by ID and that an unknown `filter_id` returns 400 M_NOT_FOUND.

- **feat(conformance): room-version-specific PDU content hash verification:** Inbound federation transactions now verify the `hashes.sha256` field on PDUs against the room-version-specific content hash algorithm before persisting. PDUs with missing or incorrect content hashes are rejected with a structured error. Conformance fixtures cover: valid hash accepted, missing hash rejected, incorrect hash rejected (per Matrix v1.18 SS API).

- **feat(conformance): outbound federation transaction conformance:** Added conformance fixtures for outbound `PUT /_matrix/federation/v1/send/{txnId}` delivery: correct transaction envelope shape, PDU wrapping, and retry behavior on transient errors.

## 0.7.2

- **fix(tests): update smoke and integration tests for retired seccomp exception and live remote fetch:** The hardening smoke test checked for `seccomp=alpha_exception`; updated to `grep -qE "seccomp=(enabled|unknown)"` to pass on both Linux (filter applied → `enabled`) and non-Linux/dry-run (`unknown`). The remote media integration test expected `"remote media fetch disabled"` (old stub behavior); updated to assert `"server discovery failed"` (live discovery attempted and correctly rejected for `remote.example.org`).

- **feat(ci): promote CI to explicit capability gates (conformance, packaging, signed release):** Three named gate steps added to both `linux-build-and-test` and `fedora-build-and-test` CI jobs after the main build step. `Conformance gate` runs `check-conformance-gate.sh` (new script), which re-invokes `meson test … conformance-tests` so conformance failures surface as a distinct named step rather than being buried in the general build output. `Packaging sanity gate` runs `meson test … packages-workflow-tooling` explicitly, which validates that version strings in RPM spec, FreeBSD manifest, and build scripts are consistent with `meson.build`. `Check release readiness metadata` (existing step) is extended to verify that the release workflow attaches SLSA provenance via `actions/attest-build-provenance`, carries `attestations: write` permission, and generates sha256sum/sha256 checksums for Linux and FreeBSD artifacts respectively. Tooling tests in `test_ci_workflow.py` and `test_release_workflow.py` assert all new gates are present.

- **feat(media): live remote media transport and accurate thumbnail metadata:** The homeserver now fetches remote media over the network instead of returning 502. `fetch_remote_media_live()` in `media_service.cpp` resolves the origin server via federation server discovery (`.well-known` / SRV / direct), performs `GET /_matrix/media/v3/download/{server}/{mediaId}` via `OutboundClient::perform()`, extracts the `Content-Type` header (case-insensitive), and hands the bytes to `fetch_remote_media()` for local ingest. The same live path serves remote thumbnail requests; no resampling is applied (original blob served). Thumbnail records in `repository.cpp` now store the actual content type and true byte size instead of the previous placeholder `"image/png"` / 4096-byte cap; dimensions remain 0×0 until an image decoder is linked.

- **feat(hardening): retire `seccomp` alpha exception:** Applied a Linux seccomp-bpf syscall allowlist via `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER, …)` in `run_server()` before listeners bind (`src/platform/seccomp_hardening.cpp`). The allowlist covers ~140 syscalls across I/O, filesystem, memory, network, threads, signals, and security operations. Default action is `SECCOMP_RET_LOG` for safe beta deployment — unrecognised syscalls are written to the kernel audit log but allowed. The `seccomp` hardening self-check now uses a `/proc/self/status` probe (`Seccomp: 2` = filter mode active), reporting `enabled` on x86-64 Linux; `unknown` on non-Linux or dry-run. The check is no longer `alpha_exception`. Unit tests cover all probe-to-check mappings and verify probe execution against the running test binary.

- **feat(hardening): retire `linker hardening` and `RELRO` alpha exceptions:** Implemented a runtime ELF program-header probe (`src/platform/elf_probe.cpp`) that opens `/proc/self/exe` on Linux and walks the 64-bit program and dynamic sections. The `linker hardening` self-check now reports `enabled` when `PT_GNU_RELRO`, `DT_BIND_NOW` / `DF_BIND_NOW`, and `PT_GNU_STACK` (without `PF_X`) are all present; `unknown` otherwise (static build, dev build without `-z,relro`, or non-Linux). The `RELRO` check reports `enabled` when `PT_GNU_RELRO` is present, `unknown` otherwise. Both are no longer `alpha_exception`, removing two production blockers from packaged hardened builds. Unit tests cover all probe-to-check mappings and verify the probe executes successfully against the running test binary on Linux.

- **feat(conformance): `GET /query/directory` promoted to spec-covered:** Implemented `GET /_matrix/federation/v1/query/directory` end-to-end: added `query_directory` to `FederationEndpoint`, added `FederationDirectory` result struct and `DirectoryQueryProvider` callback to `FederationRuntimeState`, wired routing in `transactions.cpp`, and added handler in `inbound_request.cpp`. Three conformance scenarios cover: 200 with `room_id` + `servers` when alias is known, 404 when alias is unknown, and 501 when no provider is installed.
- **feat(conformance): `make_join` 400 M_INCOMPATIBLE_ROOM_VERSION:** Extended `handle_make_membership` to return 400 with `errcode: M_INCOMPATIBLE_ROOM_VERSION` and a `room_version` field when the joining server's `ver` list does not include the room's actual version. The spec requires this error so the joining server can retry with the correct version. Conformance scenario added.
- **feat(conformance): `GET /voip/turnServer` authentication requirement:** Added a conformance scenario asserting that unauthenticated requests to `GET /_matrix/client/v3/voip/turnServer` are rejected with 401 M_MISSING_TOKEN. The endpoint is gated by the existing client-server auth guard.

## 0.7.1

- **feat(conformance): inbound transaction idempotency — 200 for duplicate txnId:** Added a conformance fixture for `PUT /_matrix/federation/v1/send/{txnId}`. The spec states the sending server must retry the same `txnId` until it receives 200 before advancing; the receiver must therefore respond 200 for a repeated `txnId`. Both requests assert 200. The `pdu_sink` deduplication invariant (sink invoked once, not twice) is separately covered by the existing unit test `Inbound federation transaction accepts signed public trusted remotes`.
- **feat(conformance): unrecognized EDU type does not cause non-200:** Added a conformance fixture verifying that a transaction containing an unknown `edu_type` returns 200. The spec documents 200 as the only valid response, stating "The server is to use this response even in the event of one or more PDUs failing to be processed"; unprocessable EDU types fall under the same contract.
- **feat(unit): unknown EDU type is not forwarded to the edu_sink:** Added `test_federation_inbound_request.cpp` unit test asserting that an unknown `edu_type` is filtered before the `edu_sink` is invoked. This is implementation policy (not a spec MUST), so it belongs in unit tests rather than conformance tests.
- **fix(conformance): remove incorrect spec citations from federation transaction tests:** Corrected three conformance scenarios that cited spec MUSTs not present in Matrix v1.18: (1) "Servers MUST treat already-processed transactions as successful again" — not in spec; (2) "Unknown EDU types MUST be silently discarded" — not in spec; (3) "Servers MUST enforce a maximum transaction size" — spec limits are count-based (50 PDUs / 100 EDUs), not byte-based. The byte-limit enforcement is already tested by the unit test `Federation transaction validation accepts bounded transactions and rejects malformed ones`.

## 0.7.0

- **feat(conformance): receipt endpoint promoted to spec-covered:** Added Catch2 BDD conformance fixtures for `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}` covering all three valid receipt types (`m.read`, `m.read.private`, `m.fully_read`), the 403 response for non-members, and a 400 `M_INVALID_PARAM` rejection for unrecognized receipt types. The handler now validates the receipt type against the spec-defined enum before storing or federating any receipt state.
- **feat(conformance): user_directory/search promoted to spec-covered:** Added Catch2 BDD conformance fixtures for `POST /user_directory/search` covering the required response shape (`results` array, `limited` boolean), user_id match, display-name match, empty results for non-matching terms, and per-entry `user_id` presence requirement.
- **feat(conformance): key rotation and publication conformance fixtures:** Added three new scenarios to `test_key_publication_conformance.cpp` covering the Matrix v1.18 key rotation contract: `verify_keys` key IDs must follow the `ed25519:version` naming convention, `valid_until_ts` must be strictly in the future (servers MUST NOT publish an already-expired key), and `old_verify_keys` entries must contain both `key` and `expired_ts` fields with `expired_ts` in the past.

## 0.6.5

- **feat(packaging): install service and create `merovingian` user/group on all package formats:** Debian, RPM, FreeBSD pkg, OpenBSD ports, and NetBSD pkgsrc now all create the `merovingian` system user and group on install, set up data/log directories with correct ownership, install the service file to the platform-canonical location, and enable the service so `service start` / `systemctl start` / `rcctl start` work without manual steps.
- **fix(systemd): service failed to start due to missing `/run/merovingian`:** The unit listed `/run/merovingian` in `ReadWritePaths` but never created it, causing systemd namespace setup to fail with `status=226/NAMESPACE` on every start. Fixed by adding `RuntimeDirectory=merovingian` (systemd creates and owns the directory before each start) and removing the now-redundant `ReadWritePaths` entry.

## 0.6.4

- **Fix (client verification — `device_lists.changed` missing after key/signature upload):** `POST /keys/device_signing/upload` and `POST /keys/signatures/upload` now emit `device_lists.changed` in `/sync` per spec §11.11.1. Previously neither endpoint called `record_device_list_change`, so the user's other devices never learned about the new cross-signing identity and could not complete the self-signature query needed to finish verification. The fix adds a self-notification (`observer = subject = user`) so all of the user's devices see the change, plus the room-member fan-out and federation broadcast.

## 0.6.3

- **Fix (client verification — `POST /keys/device_signing/upload` UIA):** Cross-signing key upload now requires User-Interactive Authentication (UIA) per Matrix spec §11.12.1. A request without an `auth` object returns `401` with the `m.login.password` flow challenge; only requests with a verified password proceed to key storage. This prevents a malicious actor from silently replacing a user's cross-signing keys and blocking verification.

- **Fix (client verification — `user_signing_key` leaked to non-owners):** `POST /keys/query` now guards `user_signing_key` with an owner check per spec §11.11.3. Previously the key was returned to any querying user; it is now only included when the requesting user matches the queried user. `handle_key_query` receives the authenticated `requesting_user` identity via a new parameter, and the call site at `handle_key_api_route` passes it through.

- **Fix (client verification — `sendToDevice "*"` not expanded):** `PUT /sendToDevice` with device_id `"*"` now correctly delivers the to-device event to every device registered to the target user, per spec §10.5. Previously `"*"` was treated as a literal device ID and sent to no real device. The fix iterates `persistent_store.devices` filtering by `user_id` and enqueues one message per device.

## 0.6.2

- **Fix (Bug 11 — OTK upload without device identity):** `key_object_is_signed_by` in
  `client_server.cpp` previously returned `true` when `signing_key_id` was empty, allowing
  `signed_curve25519` one-time and fallback keys to be accepted on a first-ever upload where
  no device identity was available. It now returns `false`, rejecting the OTK with
  `400 M_INVALID_SIGNATURE`. The signing key is always resolved from the in-body `device_keys`
  or the persistent store before verification; no key means no acceptance.

- **Fix (Bug 12 — rate limit bucket bypassed by query parameters):** `normalized_target` now
  strips the query string before computing the rate-limit bucket key, so
  `/_matrix/client/v3/sync?timeout=0` and `/_matrix/client/v3/sync?timeout=30000` share the
  same per-IP counter. Previously each unique query string created a fresh bucket, allowing
  unlimited requests by varying `?timeout` or any other query parameter.

- **Fix (Bug 13 — `compose_signed_event` silently created fallback events):** `compose_signed_event`
  in `room_service.cpp` now parses `client_event_json` as canonical JSON and returns
  `std::nullopt` when the body is not a valid JSON object. The caller propagates this as
  `400 M_BAD_JSON`. Previously it wrapped the raw invalid body into a fabricated
  `m.room.message` and persisted it, potentially silently corrupting the room timeline.

- **Fix (Bug 14 — transaction ID idempotency incomplete):** Room-send `PUT` requests and
  send-to-device `PUT` requests now implement full txn-ID deduplication. A new
  `client_txn_ids` table (migration 006) stores `(user_id, room_id, event_type, txn_id,
  event_id)`. Handlers check for a prior record before processing; on a hit they replay
  the original response immediately. After a successful send the record is stored.
  `room_id` is the empty string sentinel for to-device entries. Both SQLite and PostgreSQL
  backends hydrate the table on startup.

- **Tests (Bug 11):** Conformance scenario `keys/upload rejects signed_curve25519 OTKs when
  no device identity has been established` in `test_client_server_conformance.cpp`.

- **Tests (Bug 12):** Conformance scenario `rate limiting uses the path without query
  parameters as the bucket key` in `test_client_server_conformance.cpp`.

- **Tests (Bug 13):** Conformance scenario `room send rejects non-object bodies and does not
  create a fallback event` in `test_client_server_conformance.cpp`.

- **Tests (Bug 14):** Conformance scenarios `room send PUT replays the original event_id when
  the same transaction ID is reused` and `send-to-device PUT is idempotent: retrying the same
  txn_id does not re-queue the message` in `test_client_server_conformance.cpp`.

## 0.6.1

- **Fix (supply chain — SLSA provenance for rolling builds):** `packages.yml` now runs
  `actions/attest-build-provenance@v2` on each package artifact (`.deb`, `.rpm`, FreeBSD `.pkg`,
  static Linux tarball) before uploading. Previously only tagged alpha releases in `release.yml`
  carried SLSA provenance attestations; rolling `latest` builds had none. All attestations are
  verifiable with `gh attestation verify <file> --repo OMG-Software/Merovingian`.

- **Fix (supply chain — SBOM release attachment):** `sbom.yml` now uploads the generated SPDX and
  CycloneDX SBOM files directly to the triggering GitHub release when the workflow runs on a
  `release` event (`gh release upload`). Previously SBOMs were only stored as ephemeral workflow
  artifacts and were not attached to the published release.

- **Docs (release-process.md):** Updated to reflect that SLSA provenance attestations are
  implemented for both tagged and rolling releases, SBOMs are now attached to tagged releases,
  and corrected the "Production work that remains open" section to remove items that are now done.

- **Fix (C2 — hardcoded room version in send_join/leave/knock):** `handle_send_membership` in
  `inbound_request.cpp` was calling `parse_inbound_pdu_envelope(body)` (the zero-arg overload)
  which silently defaulted to room version "12" for all send_join, send_leave, and send_knock PDUs.
  It now queries `runtime.room_version_resolver(room_id)` first and passes the resolved version to
  the two-arg overload, matching the behaviour already present in the transaction processing path
  (fixed in v0.5.36). PDUs from rooms using earlier room versions (v10, v11) are now correctly
  parsed and verified against their actual version rules.

- **Tests (C2):** New conformance scenario `send_join passes the resolved room version to the
  membership acceptor envelope` in `test_federation_conformance.cpp` — wires a resolver returning
  "10", calls send_join, and asserts `envelope.room_version == "10"`.

- **Tests (E2EE OTK signature):** New conformance scenario `POST /keys/upload rejects a one-time
  key whose signature bytes fail Ed25519 verification` in `test_client_server_conformance.cpp` —
  uploads a device key with a 32-zero-byte ed25519 public key and an OTK with a 64-zero-byte
  (cryptographically invalid) signature under the correct key ID; asserts the server returns
  `400 M_INVALID_SIGNATURE`. Confirms that the fix from v0.5.25 (real Ed25519 verification
  via `key_object_is_signed_by`) is covered by a regression test.

## 0.6.0

- **Fix (federation invite dispatch):** `POST /rooms/{roomId}/invite` now dispatches
  `PUT /_matrix/federation/v1/invite/{roomId}/{eventId}` to the remote homeserver when the
  invitee is on a different server. Previously the invite event was persisted locally but never
  sent to the remote server, so the invitee's client never received it. The dispatch is
  asynchronous via the outbound transaction queue, mirroring the pattern already used in
  `createRoom`. A new `room_version_from_store` helper reads the room's version from its
  `m.room.create` state event to select the correct v1/v2 invite wire format.

- **Feature (POST /publicRooms):** Implemented `POST /_matrix/client/v3/publicRooms` per
  [spec §post_matrixclientv3publicrooms](docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3publicrooms).
  Accepts `filter.generic_search_term` (case-insensitive substring match on room name, topic,
  canonical alias, and room_id), `limit` (max results per page), and `since` (integer-offset
  pagination token); returns `next_batch` when more results follow. Refactored the existing
  `public_rooms_json` helper into `public_rooms_filtered_json` shared by both GET and POST.
  Two conformance gap-placeholder tests replaced with real spec assertions.

- **Fix (member visibility — startup state repair):** Added `repair_missing_state_entries` called
  at the end of `hydrate_local_database`. This scans all events in `persistent_store.events`,
  identifies state events (JSON contains a `"state_key"` field) that have no corresponding entry
  in `persistent_store.state`, and creates those missing entries using the event with the highest
  `stream_ordering` for each `(room_id, type, state_key)` tuple. Fixes rooms where the old
  `!state_key.empty()` bug silently dropped `m.room.create`, `m.room.power_levels`, and
  `m.room.join_rules` from state on the initial send_join, leaving `build_pdu_auth_event_map`
  unable to find the create event and causing auth step 2 to reject all subsequent inbound PDUs.

- **Fix (remote member tracking in pdu_sink):** `pdu_sink` now calls `upsert_membership` and
  updates `LocalRoom.members` when an accepted inbound PDU is an `m.room.member` state event.
  Previously, remote joins accepted via federation were stored in `persistent_store.events` and
  `persistent_store.state` but not in `persistent_store.memberships` or `LocalRoom.members`. After
  a server restart, `hydrate_local_database` would rebuild `LocalRoom.members` from memberships
  only, losing all remote members — breaking `GET /rooms/{roomId}/members`, sync, and outbound
  federation dispatch for those users.

## 0.5.37

- **Fix (C1 — relayed PDU signature bypass):** `authorize_federation_pdu()` previously
  skipped Ed25519 verification for relayed PDUs (where `sender_domain(pdu.sender)` differs
  from the transport origin). The condition now checks `key->server_name == pdu_sender_domain`
  instead of `pdu_sender_domain == expected_origin`, and the transaction loop resolves the
  sender domain's signing key via `remote_key_resolver` before calling the authorizer. When
  the resolver is wired but cannot produce a key the PDU is rejected fail-closed; when no
  resolver is wired the structural presence-check is unchanged (known limitation for partial
  deployments).

- **Fix (C2 — missing event-auth before PDU persistence):** The production `pdu_sink` in
  `wire_federation_callbacks_impl` now calls `authorize_event_against_auth_events` against
  the room's current resolved state before calling `store_event_with_state`. Events that
  fail auth return `rejected_auth` so the federation handler audits the rejection without
  issuing a non-200 HTTP status (which would cause the remote to back off all federation).
  A `build_pdu_auth_event_map` helper mirrors the same pattern already used in
  `room_service.cpp` for locally-created events.

- **Fix (C3 — v12 m.room.create stored with empty room_id after send_join):**
  `ingest_send_join_state` and the auth_chain loop in `join_room` stored the
  `m.room.create` state row with `room_id=""` for v12 rooms because the create
  event carries no `room_id` field (MSC4291). `build_pdu_auth_event_map` filters
  state by `room_id == envelope.room_id` and missed it, so `auth_events.create`
  was always null. Every inbound PDU for a v12 federated room was then rejected
  at event-auth step 2: "room has no create event". Fix: when
  `policy.create_event_is_room_id` and `parsed.event.room_id` is empty, derive
  `room_id = "!" + event_id.substr(1)` before persisting the state row. The
  auth_chain loop also gains the correct JSON-field-presence check for state_key
  (was `!state_key.empty()`, which silently dropped all empty-state-key events).

## 0.5.36

- **Fix (inbound PDU signature rejection for v10 rooms):** The
  `room_version_resolver` callback in `FederationRuntimeState` was never wired,
  causing every inbound PDU to be parsed and verified as room version 12.
  Rooms at version 10 (the Synapse default for existing rooms) include `"origin"`
  as a top-level field in the signing payload; the v12 redaction algorithm strips
  it, producing a different canonical hash and a false signature failure.  Every
  inbound event for the old room was rejected with a per-PDU error buried in the
  200 OK transaction response body, so remote servers never backed off — they
  kept delivering events that Merovingian silently discarded.  The resolver is
  now wired to `room_version_from_store`, which reads the room version from the
  stored `m.room.create` state event and falls back to `"10"` for legacy rooms.

## 0.5.35

- **Fix (typing state not cleared on message send):** When a user successfully
  sends a message, the server now clears their `typing=true` state for that
  room (CS API §11.12: the server MUST send a stop-typing event when a user
  sends a message). Local `typing_users` state is set to `false`, a
  `typing:false` EDU is federated to all remote servers in the room, and the
  sync notifier is woken so local clients receive the stop-typing event
  immediately. Stale typing indicators (e.g. "X is typing…" persisting after
  X sends a message) are no longer shown to remote users.

## 0.5.34

- **Fix (`DELETE /devices/{deviceId}` — bypasses UIA):** The endpoint deleted
  devices after bearer-token auth alone, with no re-authentication step. The
  spec (§10.7.1) requires User-Interactive Authentication with
  `m.login.password` before any device can be deleted. A bare request now
  returns 401 with the UIA challenge; only a valid `auth.password` proceeds to
  deletion.
- **Fix (key backup version hardcoded to `"1"`):** `POST /room_keys/version`
  now generates a unique, monotonically-increasing version string per user (e.g.
  `"1"`, `"2"`, …) instead of always returning `"1"`. `PUT /room_keys/version/{ver}`
  uses the path version for updates. Session operations (`PUT`/`DELETE`
  `/room_keys/keys/…`) require and honour the `?version=` query parameter as
  the spec mandates. The update response now also includes the `"version"` field
  in the `RoomKeysUpdateResponse` body.
- **Fix (`PUT /typing` — invalid room/user state accepted; EDU type wrong):**
  The handler now validates room existence and membership before storing typing
  state, returning 403 M_FORBIDDEN for non-members and unknown rooms. It also
  parses `typing` (bool) and `timeout` from the request body. The federation
  EDU now encodes `typing` as a JSON boolean (`true`/`false`) instead of the
  string `"true"`, matching the Matrix federation spec.
- **Fix (`POST /read_markers` — `m.read` and `m.read.private` ignored):** The
  handler previously only processed `m.fully_read`. It now processes all three
  marker types: `m.read` (federated as a receipt EDU), `m.fully_read` (local
  account-data marker), and `m.read.private` (local-only receipt, not
  federated).
- **Fix (receipts and read markers — no room/membership validation):** Both
  `POST /rooms/{roomId}/receipt/{type}/{eventId}` and
  `POST /rooms/{roomId}/read_markers` now reject requests from users who are
  not current members of the room with 403 M_FORBIDDEN, instead of silently
  storing ephemeral state for rooms the caller does not belong to.
  `m.read.private` receipt type is also now correctly excluded from outbound
  federation EDUs.

## 0.5.33

- **Fix (`GET /rooms/{roomId}/members` — missing access check):** The endpoint
  returned membership data to any authenticated user regardless of whether they
  were a current or previous member of the room. The spec (§11.1) requires 403
  M_FORBIDDEN for callers who have never been a member. The fix checks both
  `store.memberships` (current state) and `store.state` (historical
  `m.room.member` events) before returning data.
- **Fix (`POST /account/password` — no UIA):** The endpoint accepted
  `new_password` without first verifying the account owner via the
  User-Interactive Authentication API. The fix adds a full UIA round-trip: a
  bare request returns 401 with the `m.login.password` flow; the client must
  supply `auth.type`, `auth.identifier`, and `auth.password` (current password)
  before the change is applied.
- **Fix (registration ignores `device_id`, `initial_device_display_name`,
  `inhibit_login`):** The parser now extracts all three fields. When
  `inhibit_login` is true only `user_id` is returned. Otherwise the
  client-supplied `device_id` is used (or a generated one if absent), the
  display name is stored, and the session is added to `rt.devices` so it
  appears in `GET /devices`.
- **Fix (registration always demands token UIA):** The `m.login.registration_token`
  UIA challenge is now conditional on `security.registration.require_token`.
  Code paths that cannot reach open registration (blocked by config validation)
  are now correctly handled at the handler level too.
- **Fix (`POST /login` ignores `initial_device_display_name`):** The login
  parser now extracts the field and passes it to `rt.devices` when creating a
  new device record, so `GET /devices` reflects the client-chosen display name.

## 0.5.32

- **Fix (federated room leave — 403 on leave after server restart):** `leave_room`
  returned 403 "user is not joined or invited" when the membership row was absent
  from `persistent_store.memberships`. This happened when the server restarted
  between `store_room` and `store_membership` during a federated join (non-atomic
  write sequence). The fix checks `persistent_store.state` for an `m.room.member`
  event confirming `membership: join` and synthesises the missing row before
  proceeding, so the user can leave without manual intervention.
- **Fix (federated room leave — no outbound leave event):** `leave_room` called
  `persist_membership_transition` (local-only) for rooms on remote servers. The
  remote server was never notified of the departure. For remote rooms `leave_room`
  now executes the full Matrix federated-leave flow: `GET make_leave` to obtain a
  signed leave-event template, add content hash, sign with the server key, then
  `PUT send_leave` to deliver the event to the resident server before updating
  local state.
- Add `ValidatedMakeLeaveResponse` / `validate_make_leave_response` public API
  mirroring the existing join validation surface.
- **Docs:** Deleted `docs/01-progress-tracker.md`. All open TODO items extracted
  into `docs/todos/` (`priorities.md`, `beta-milestone.md`,
  `production-milestone.md`, `capability-gaps.md`). References updated across
  `CLAUDE.md`, `AGENTS.md`, `README.md`, and all live doc files.

## 0.5.31

- **Fix (cross-server E2EE decryption failure):** `m.device_list_update` EDUs
  were sent without the `keys` field. When a Merovingian user uploaded device
  keys, remote servers (e.g. Synapse) had to schedule an asynchronous
  `GET /_matrix/federation/v1/user/devices/{userId}` refetch before they could
  encrypt to that device. If a remote client encrypted during the refetch window
  it used stale or empty device keys, producing `OlmError::MissingCiphertext` on
  the Merovingian-side recipient — cross-server messages could not be decrypted.
  Fixed by including the device identity keys object in every `m.device_list_update`
  EDU so the remote server can update its cache immediately without a separate
  fetch (Matrix spec v1.18 §m.device_list_update `keys` field).
- **Fix (`stream_id` hardcoded to 0 in `GET /user/devices`):**
  `build_user_devices_response` always returned `"stream_id": 0` regardless of
  the actual device-list version. Remote servers use this value to detect gaps
  between device-list-update EDUs; a constant zero caused every incoming EDU to
  appear to require a refetch. Now reflects `store.next_sync_stream_id`.

## 0.5.30

- **Fix (CORS missing on non-OPTIONS responses):** `complete()` and `sync_json()`
  returned `DispatchResult` without calling `apply_cors_headers()`, so browsers
  silently discarded `200 /sync` response bodies and could not read `4xx` error
  payloads from the key API and other routes. Only `dispatch_resp` / `dispatch_err`
  applied CORS, meaning OPTIONS preflights succeeded but the actual responses that
  followed were CORS-blocked. Fixed by renaming the implementation to
  `handle_client_server_request_impl` (static) and adding a public wrapper that
  calls `apply_cors_headers` on every `complete` result — a single boundary
  covering all code paths. Three new BDD scenarios verify CORS on `GET /versions`
  (unauthenticated 200), `GET /sync` (authenticated 200), and
  `GET /room_keys/version` (authenticated 404).

## 0.5.29

- **Fix (CORS regression):** PR #218 activated previously-dormant CORS code by
  populating `req.headers` for the first time. With the default
  `cors.allowed_origins=*`, Merovingian now emits `Access-Control-Allow-Origin`
  on every `/_matrix/` response. Reverse-proxy configs that also set this header
  (nginx `add_header`, Apache `Header always set`) produce duplicate values
  (`*, *`), which browsers reject with a CORS error — clients show "Failed to
  connect" even though the server returns HTTP 200. Updated `docs/configuration.md`
  and `config/merovingian.conf.example` to remove all proxy-level CORS directives
  and warn against re-adding them.
- **Fix (trusted-proxy documentation gap):** Without `server.trusted_proxies`,
  all traffic arriving through a reverse proxy is bucketed under the proxy's IP
  (`127.0.0.1`), collapsing all clients into a single rate-limit bucket. A
  single active Matrix client polling sync at ~60 req/min exhausts the entire
  `default_per_ip` quota, causing `429` for every other client. Added guidance
  to `merovingian.conf.example` and a "Rate limiting behind a reverse proxy"
  subsection to `docs/configuration.md`. Fixed nginx example to use `$remote_addr`
  (not `$proxy_add_x_forwarded_for`, which allows IP-bucket forgery); added
  `X-Forwarded-For` to the Apache example which previously omitted it entirely.
- **Config (rate-limit default):** Raised `client_rate_limits.default_per_ip`
  default from `60/60s` to `90/60s` to accommodate typical Matrix client
  behaviour (sync loop + periodic `/versions` health-check) without requiring
  manual config adjustment.

## 0.5.28

- **Security (Finding 5 — Per-IP rate limiting):** `LocalHttpRequest` had no
  `remote_addr` field, so every unauthenticated request was bucketed under the
  synthetic key `"local|<route>"`. A single source could exhaust the
  login/register budget (default 5 per 60 s) for all other clients. Fixed by:
  (1) adding `std::string remote_addr` to `LocalHttpRequest`; (2) capturing the
  peer address via `sockaddr_storage` at `::accept()` time in both the plain and
  TLS acceptor loops and threading it through `serve_one_http_connection` →
  `serve_stream` → `build_local_request`; (3) replacing the synthetic `"local|"`
  prefix with the actual peer IP in `allow()` — keyed as
  `"<ip>|<normalised_route>"`; (4) trusted-proxy support: when `remote_addr`
  matches an entry in `server.trusted_proxies`, the leftmost `X-Forwarded-For`
  address is used instead, so downstream clients behind a reverse proxy each get
  their own bucket. New BDD scenarios: per-IP isolation (two IPs do not share a
  bucket) and trusted-proxy XFF keying.

- **Supply-chain (Finding 7 — Artifact provenance):** The alpha release workflow
  now generates a SLSA provenance attestation for each tarball via
  `actions/attest-build-provenance@v2` immediately after the checksum is written.
  Both Linux and FreeBSD build jobs were updated with `attestations: write` and
  `id-token: write` permissions. Attestations are verifiable offline with
  `gh attestation verify`. Release notes updated to reference the provenance step.

## 0.5.27

- **Bug fix (send_join state ingestion — empty state_key):** When a local user
  joined a remote room via federation, the `state[]` array from the `send_join`
  response was processed with an incorrect condition: `!parsed.event.state_key.empty()`.
  `EventEnvelope::state_key` defaults to `""` for *both* state events with
  `state_key=""` (e.g. `m.room.encryption`, `m.room.create`, `m.room.power_levels`,
  `m.room.join_rules`) *and* non-state events (where the JSON field is absent
  entirely). The check therefore silently dropped every empty-state-key event from
  the state table. Only membership events (whose `state_key` is a user ID) were
  written correctly.

  Consequence: after a federated join, `store.state` contained only membership rows.
  The post-join sync omitted `m.room.encryption` from the room state, preventing
  E2E encryption setup — the joining user could not decrypt room content or send
  messages.

  Fix: extracted the state ingestion loop into `ingest_send_join_state()` and
  replaced the `.empty()` check with a raw-JSON `"state_key"` field-presence check
  via `json_string_member(*entry_obj, "state_key") != nullptr`. A state event is any
  event whose JSON carries a `"state_key"` field, regardless of whether its value is
  empty. Added a BDD regression test (`ingest_send_join_state writes empty-state-key
  events to store.state`) in `tests/unit/test_federation_invite_join.cpp`.

## 0.5.25

- **Security (Finding 3 — Federation PDU relay):** `authorize_federation_pdu()`
  was rejecting any PDU where `sender_domain(pdu.sender) != expected_origin`,
  which incorrectly blocked legitimate relayed PDUs (backfill, missing-events,
  normal propagation via relay servers). The constraint is not required by the
  Matrix spec — only the sender's homeserver signature matters. Removed the
  domain-equality check; signature verification now uses `pdu_sender_domain`
  instead of `expected_origin`, and crypto verify is guarded to the case where
  both are equal (i.e. non-relayed PDUs). Added conformance BDD scenarios
  covering the relay-accept and sender-mismatch-reject cases.

- **Security (Finding 4 — OTK signature verification):** `key_object_is_signed_by()`
  was only checking that the correct key ID *existed* in the `signatures` map —
  it never called `crypto_sign_verify_detached`. OTK and fallback keys uploaded
  via `POST /keys/upload` therefore passed validation with any garbage bytes
  under the right key ID. Fixed: the function now decodes the signature and the
  device's Ed25519 public key from unpadded base64, verifies sizes, strips the
  `signatures` field from a copy of the key object, serialises to canonical JSON,
  and calls `crypto_sign_verify_detached`. Returns `false` on any step failure.
  All test helpers updated to produce real Ed25519 signatures via
  `merovingian::federation::test::make_signed_otk_json` /
  `make_signed_fallback_key_json` from the shared support header.

- **Correctness (Finding 6 — Room version hardcoded to "12"):**
  `parse_federation_pdu()` and `parse_inbound_pdu_envelope()` both hardcoded
  room version `"12"` for event-ID computation and auth-rule selection. For
  rooms on older versions (v10, v11) this produces wrong event IDs and applies
  the wrong redaction rules. Fixed: added `RoomVersionResolver` callback type
  and `room_version_resolver` field to `FederationRuntimeState`; added a
  `parse_federation_pdu(encoded, resolver)` overload; the resolver is called
  with the parsed `room_id` to look up the room's `m.room.create` state.
  Falls back to `"12"` when the room is unknown or no resolver is wired.
  `parse_inbound_pdu_envelope()` likewise accepts an explicit version string.
  Added BDD scenario confirming the resolver is used during transaction handling.

## 0.5.24

- **Fix (E2EE):** Merovingian never sent `m.device_list_update` EDUs to remote
  servers. When a local user uploaded device keys or joined a room, Synapse (and
  any other remote homeserver) was never notified, so remote servers never queried
  the user's devices, never claimed one-time keys, and therefore never delivered
  encrypted room keys. Clients on the local server could not decrypt any messages
  from federated encrypted rooms.

  **Fix**: Added `remote_servers_for_user` (collects distinct remote servers from
  all rooms a user is in), `broadcast_device_list_updates` (builds an
  `m.device_list_update` EDU per device and dispatches it to each destination),
  and two call sites: one in `handle_key_upload` (keys uploaded) and one in the
  `/rooms/{roomId}/join` and `/join/{roomIdOrAlias}` handlers (user joined room).

  **Tests**: Three new BDD scenarios in `test_outbound_dispatch.cpp`:
  (1) key upload with a remote room member dispatches `m.device_list_update`;
  (2) key upload with only local room members dispatches nothing;
  (3) local join to a room containing a remote member dispatches
  `m.device_list_update` for the joining user.

## 0.5.23

- **Security:** Raw access token no longer persisted to audit log on rate-limit
  or auth rejection. `authenticated_user()` now resolves the token to a
  `user_id` (or `"<unknown>"`) before calling `log_diagnostic_audit`; the
  bearer token string is never written to `audit_log`.
- **Security:** Shallow federation PDU authorization removed. `pdu_is_authorized()`
  was comparing the event type against a hardcoded room-version-12 policy with
  a synthetic power level of `{50, 0}` — it did not use the room's actual auth
  state. The function is renamed `pdu_passes_transport_checks()` to correctly
  scope its responsibility; a TODO for full event-auth at the sink is added.

## 0.5.22

- Fix federated join from invite leaving room invisible to incremental sync.
  After a successful make_join/send_join the local join event was never stored
  in `store.events` or `current_state`. `joined_membership_changed_since` reads
  `current_state` to find the user's m.room.member entry; without the fix it
  still pointed at the old invite event (membership="invite"), so the function
  returned false and the room was silently suppressed from `rooms.join` in every
  incremental sync once the client's `since` token caught up to the event
  stream position. Fix: `room_service.cpp::join_room` now calls
  `store_event_with_state` for the signed join event before `store_membership`,
  which atomically inserts the event and updates `current_state` to point at
  the join event_id. `joined_membership_changed_since` then correctly finds
  membership="join" at `membership_stream > since_ordering`.

## 0.5.21

- Fix Codecov upload silently failing on every push to `main`: coverage
  was generated correctly (76% lines, 88% functions) but the upload step
  returned `{"message":"Token required because branch is protected"}` and
  `fail_ci_if_error: false` swallowed it. Added `token: ${{ secrets.CODECOV_TOKEN }}`,
  set `disable_search: true` to prevent a redundant second gcov pass, and
  flipped `fail_ci_if_error: true` so future failures are visible.
  Added `.codecov.yml` with a 60% line-coverage floor, 50% patch target,
  and ignore rules for tests, packaging, and scripts.
  **Action required**: add `CODECOV_TOKEN` as a repository secret from
  https://app.codecov.io/gh/OMG-Software/Merovingian → Settings.

- Fix misleading redaction conformance header: `prev_state` was missing
  from the v1–v10 preserved top-level fields list; `m.room.join_rules`
  incorrectly showed only `join_rule` instead of `join_rule, allow` for
  v8–v10. Added explicit `REQUIRE_FALSE(invite)` assertion to the v10
  `m.room.power_levels` scenario (field was present in fixture but untested).

## 0.5.20

- Fix federated join stale membership loop: two related bugs caused a Merovingian user
  invited to a Synapse-hosted room to enter an infinite invite loop where `POST /join`
  returned 200 OK but the room never appeared in sync.

  **Bug 1 — invite handler downgraded "join" to "invite"**: When the remote server
  re-sent an invite for a user already persistently "join" in that room (state divergence),
  `upsert_membership` unconditionally overwrote "join" with "invite". `store_event_with_state`
  then replaced the `m.room.member` state entry with the invite event. After this,
  `joined_membership_changed_since` saw membership=invite, the room was suppressed from
  `rooms.join`, and sync returned an empty invite the user couldn't dismiss.
  Fix: the invite handler now checks for an existing "join" membership before calling
  `upsert_membership`; if the user is already joined it signs and returns the event
  cooperatively without altering any local state.

  **Bug 2 — `already_member` path ignored persistent membership**: `join_room` gated the
  federation join path purely on `find_room` returning null. If the in-memory `LocalRoom`
  existed (from a previous join) but the persistent membership record was "invite" (from
  Bug 1 or restart), `room_has_member` returned true and the code took the `already_member`
  shortcut, returning 200 OK without federating. `delete_invite` then removed the invite
  metadata, leaving membership="invite" with no invite state — 380-byte sync responses for
  ever. Fix: before the `if (room == nullptr)` federation branch, a new guard checks whether
  the room is remote AND the user's persistent membership is not "join". If so, the stale
  `LocalRoom` is erased and `room` is set to null so the full make_join → send_join flow
  runs, re-establishing membership on both the local server and the remote.

  Two regression tests added to `test_federation_invite_join.cpp` covering both bugs.

## 0.5.19

- Fix `m.room.join_rules` redaction: the `allow` field (restricted joins, MSC3083) must be
  preserved in room versions 8–10 as well as v11+. Split `RedactionRules::room_v1_v10` into
  `room_v1_v7` (join_rule only) and `room_v8_v10` (join_rule + allow); updated the version
  table accordingly. The incorrect "v1-v10 join_rules" conformance test was renamed "v1-v7" and
  a new "v8-v10" scenario added asserting both fields survive.
- Fix v12 auth-rule conformance fixtures: many `m.room.power_levels` auth-state fixtures put
  `@alice:example.org` (the room creator) in `content.users`, which is impossible in room v12
  where creators hold implicit infinite power and MUST NOT appear in `content.users`. Changed
  all affected entries to `@moderator:example.org` so the fixture represents a reachable v12
  room state; all "reject" scenarios already used `@admin` as the creator.
- Add wildcard type-pattern matching to `event_passes_filter` per the Matrix CS API v1.18 spec:
  bare `*` matches all event types; `prefix*` matches any type starting with that prefix.
  Senders continue to use exact matching. Added four conformance scenarios covering `*`,
  `m.room.*`, `m.*` in `not_types`, and mixed exact-plus-wildcard lists.

## 0.5.18

- Fix `scripts/reject-unsafe.sh` CI gate scanning non-C++ files: `grep -R`
  over `include/ src/ tests/` now includes `--include='*.cpp'` / `*.hpp` /
  `*.h` / `*.cc` / `*.c` flags so Python test scripts and other non-C++ files
  containing JavaScript/shell `new`, `delete`, `free`, `malloc` keywords do not
  trigger false positives.

## 0.5.17

- Fix four conformance-test accuracy issues identified by code review:
  - **v1 auth fixture**: `make_create_event()` produces a v12 PDU (no `room_id`); added
    `make_v1_create_event()` and `make_v1_non_federated_create_event()` with correct v1 shape
    (`room_id` present, no `room_version` in content) and updated the two v1 auth scenarios to
    use them (`test_event_auth_rules.cpp`)
  - **PDU format header**: banner comment stated `room_id` is required for all room v3+ PDUs
    without noting the v12 `m.room.create` exception; clarified with explicit exception note
    (`test_pdu_format_conformance.cpp`)
  - **Redaction assertions**: the v10 top-level scenario asserted `origin` but not `membership`
    despite both being spec-protected in v1–v10; added the missing `REQUIRE`; added a new
    `membership` / `prev_state` v10-vs-v11 comparison scenario that proves v11 strips both fields
    (`test_redaction_conformance.cpp`)
  - **Sync filter limit sentinel**: the `limit == 0` internal convention was in a `[conformance]`
    scenario alongside the real spec assertion; separated it into a `[helper]`-tagged scenario
    with a comment explaining the distinction from spec behaviour
    (`test_sync_filter_conformance.cpp`)

## 0.5.16

- Fix `GET /sync` timeline pagination, which made Element unable to render
  messages and froze Cinny (stack overflow) in rooms with history:
  - `timeline.limited` was derived from the persistent store's **total** event
    count (across all rooms) versus the page size, so any non-trivial room
    reported `limited: true` on **every** sync. matrix-js-sdk treats that as a
    gap and discards + re-fetches the live timeline each cycle ("Live timeline
    was reset"), so messages never stabilise and backfill loops can build a
    cyclic timeline that overflows the stack. `limited` is now true only when
    this sync window actually dropped older events beyond the filter limit.
  - The timeline now includes a `prev_batch` token (a stream-ordering position
    consumable by `GET /rooms/{roomId}/messages?dir=b&from=…`) so clients can
    backfill the dropped events with neither a gap nor an overlap.
  - A truncated window now returns the **most recent** events (newest history),
    not the oldest, matching client rendering expectations.
- Add `[sync][timeline]` conformance scenarios covering `limited`/`prev_batch`
  semantics and most-recent-event selection (the gap that let this ship).
- Implement `GET /_matrix/client/v3/thirdparty/protocols`. It previously 404'd,
  making clients (Element) log repeated "Failed to check for protocol support"
  errors and retry; it now returns `200 {}` (the server runs no application
  services), per the CS API spec.
- Add conformance coverage that `thirdparty/protocols` returns a 200 object, and
  that an `OPTIONS` CORS preflight on a media endpoint (`/_matrix/media/v3/config`)
  returns 200 with `Access-Control-Allow-Origin`. This pins server-side CORS as
  correct for all `/_matrix/` resources, so browser media-preflight failures
  behind a reverse proxy are a deployment/proxy concern, not a server gap.
- Document the `/_matrix/media/` reverse-proxy route in `configuration.md` for
  every example (nginx, Caddy, Traefik, HAProxy) plus a media CORS smoke test.
  The omitted media location — falling through to a catch-all `403` — was the
  real cause of browser media failures (`net::ERR_FAILED` on preflight).

## 0.5.15

- Add federation conformance test coverage for 7 previously untested endpoints:
  - GET /event/{eventId} — 200 with PDU body for known event; 404 M_NOT_FOUND unknown; 501 no provider
  - GET /state/{roomId} — 200 with state body for known room; 404 M_NOT_FOUND unknown; 501 no provider
  - GET /state_ids/{roomId} — 200 with pdu_ids + auth_chain_ids arrays; 404 unknown; 501 no provider
  - POST /get_missing_events/{roomId} — 200 with events array; 501 no provider
  - GET /query/profile — 200 with displayname+avatar_url; field=displayname filter; 404 unknown; 400 bad field; 501 no provider
  - GET /make_knock/{roomId}/{userId} — 200 with room_version + event template; 501 no provider
  - PUT /send_knock/{roomId}/{eventId} — 200 accepted; event absent from response; 501 no acceptor

## 0.5.14

- Add client-server conformance test coverage for 12 previously untested endpoints:
  - GET /devices — devices array contains device_id for every login device
  - GET /devices/{deviceId} — 200 for known, 404 M_NOT_FOUND for unknown
  - GET /capabilities — m.room_versions default and available fields
  - GET /joined_rooms — returns created room in joined_rooms array
  - GET /publicRooms — chunk array and total_room_count_estimate
  - GET /directory/room/{alias} — resolves alias to room_id+servers, 404 for unknown
  - GET /register/available — available:true free, 400 M_USER_IN_USE taken, 400 M_INVALID_USERNAME invalid
  - PUT/GET /user/{userId}/account_data/{type} — round-trip stores and retrieves; 404 for unset
  - PUT/GET /profile/{userId}/displayname — updates and reflects new displayname
  - GET /profile/{userId} — unauthenticated; returns displayname+avatar_url; 404 for unknown user
  - GET /pushrules/ — global ruleset with all five categories (override, content, room, sender, underride)
  - Standard error responses — errcode+error on 401 invalid token; 403 M_FORBIDDEN for cross-user write

## 0.5.13

- Add conformance test coverage gaps across sync filter, redaction, event auth
  rules, and state resolution:
  - Sync filter: rooms/not_rooms, state/ephemeral/account_data subfilters,
    presence filter, global account_data filter, limit parsing, include_leave.
  - Redaction: join_rules v10 vs v11+ (allow key), history_visibility preserved,
    aliases preserved v10 / stripped v11+, third_party_invite signed preserved,
    state_key preserved top-level, v12 inherits v11 rules.
  - Event auth rules: non-create event rejected without create, knock allowed
    when join_rule=knock, knock rejected when join_rule=public, kick rejected at
    equal power level, ban rejected at equal power level.
  - State resolution: v2 conflicting membership resolved to single winner,
    v2 unconflicted + conflicted partition, partition_conflicted_state splits
    shared from conflicting events.
- Fix `m.room.join_rules` redaction: `allow` key now only preserved in v11+;
  v1-v10 redaction strips it (was incorrectly preserved in all versions).
- Fix `m.room.aliases` redaction: `aliases` key now preserved in v1-v10 and
  stripped in v11+ (was stripped in all versions — no case existed).
- Fix knock event authorization: add `MembershipState::knock` enum value, wire
  `parse_membership_state("knock")` (was falling back to `leave`), add step-5
  knock block enforcing sender==state_key and join_rule is knock/knock_restricted.

## 0.5.12

- Fix canonical JSON key-sort conformance test: the scenario
  "sorts object keys by Unicode code point" claimed to cover multi-byte UTF-8
  keys (comment mentioned `é`) but the actual JSON was `{"z":3,"A":1,"a":2}` —
  all ASCII. The expected output only checked ASCII ordering.
  Replaced with a test that uses `é` (U+00E9, UTF-8: `0xC3 0xA9`) and `中`
  (U+4E2D, UTF-8: `0xE4 0xB8 0xAD`) as real keys, verifying that the
  serializer places them after all ASCII keys and in ascending byte order.
- Fix misleading `[helper]` scenario comment in sync filter conformance test:
  changed "Spec behaviour" to "Implementation helper behaviour, NOT Matrix API
  behaviour" to clarify the distinction between the lenient internal helper and
  the spec-mandated `400 M_BAD_JSON` route-level rejection.

## 0.5.11

- Split `localpart_is_valid()` into two spec-faithful validators:
  - `localpart_is_valid_new()` — enforces the Matrix v1.18 normative set
    (`a-z`, `0-9`, `._-=/+`). Rejects uppercase, empty, and all other
    characters. Used at registration time.
  - `localpart_is_valid_federated()` — accepts the historical set: any valid
    UTF-8 code point that is not `:` or NUL, with no surrogate code points.
    Empty localparts are accepted for maximum federation compatibility.
- Add `user_id_is_valid_federated()` — same structural constraints as
  `user_id_is_valid()` but uses the federated localpart validator.
- Fix `user_id_is_valid()` to call `localpart_is_valid_new()`: it previously
  accepted uppercase localparts (e.g. `@Alice:example.org`) because the
  shared helper permitted uppercase for historical reasons. The strict
  validator is now used for all local/registration paths.
- Update registration callers in `client_server.cpp` to use
  `localpart_is_valid_new()` explicitly.
- Add conformance tests: new-localpart rejection of uppercase, federated
  acceptance of `#`, `!`, Unicode, empty; rejection of `:` and NUL.

## 0.5.10

- Fix v12 `m.room.create` inbound PDU rejection: `parse_event_envelope()` required
  `room_id` for all events; v12 create events MUST NOT have `room_id`. Fixed to
  allow absent `room_id` when `type == "m.room.create"`.
- Fix v12 create event `room_id` derivation in `parse_inbound_pdu_envelope()`:
  now computes `room_id = "!" + event_id.substr(1)` for v12 create events after
  computing the reference hash (same hash body, sigil swap `$` → `!`).
- Add v12 auth_events exclusion enforcement: v12 `m.room.create` MUST NOT appear
  in any other event's `auth_events`. `parse_inbound_pdu_envelope()` now detects
  this using the deterministic relationship between `room_id` and `create_event_id`
  in v12 (no store lookup needed) and returns `nullopt` for violating PDUs.
- Fix v12 create event test fixture in `test_event_auth_rules.cpp`: removed
  `room_id` field from `make_create_event()` which incorrectly included it.
- Fix sync `GET /sync` returning no error for malformed inline filter JSON:
  when `?filter=` starts with `{` and fails to parse, the route handler now
  returns `400 M_BAD_JSON` instead of silently using a pass-all filter.
- Add event ID grammar/semantics distinction conformance test: clarifies that
  `event_id_is_valid()` is a syntax-only check; SHA-256 derived v4+ IDs are
  always exactly 44 characters.
- Add v12 PDU format conformance tests: v12 create event without `room_id` is
  accepted; v12 PDU listing the create event in `auth_events` is rejected.
- Add sync filter conformance test for the route-level JSON validation path.
- Fix canonical JSON parser to reject `-0` per Matrix v1.18 spec which says
  "numbers that are negative zero MUST NOT appear in canonical JSON." The parser
  previously accepted `-0` and silently normalised it to `0`. Three tests that
  incorrectly expected successful parsing of `-0` are corrected to expect
  `invalid_number`. The serialiser was already correct (never produces `-0`).
- Fix four conformance test issues identified by static analysis:
  (1) Localpart grammar test mislabelled uppercase `ALICE` as "Spec MUST" —
  uppercase is historical/federation compat, not normative v1.18. Split into a
  normative scenario (lowercase only) and a `[historical]` scenario.
  (2) Server discovery test asserted the rejection `reason` string must contain
  `"private"` and labelled it "Spec MUST" — the spec only mandates the
  `discovery_allowed` flag, not message content. Replaced with a non-empty check.
  (3) Sync filter `parse_filter_argument` invalid-JSON scenario was tagged
  `[conformance]` but tests internal helper leniency, not the Matrix API. Retagged
  `[helper]` with a comment clarifying where API-level 400 enforcement lives.
- Fix two missing default push rules: add `.m.rule.contains_display_name` and
  `.m.rule.roomnotif` to the server's default override ruleset. Their absence
  caused Element SDK to log "Missing default global override push rule" on every
  login and patch the rules in client-side. Both rules are MUST per the Matrix
  v1.18 CS API § Default Override Rules. Expand the `/pushrules/` conformance
  test to assert all twelve default override rules and all five underride rules
  are present.
- Fix state resolution `m.room.member` type fallback causing incorrect state
  after Codex-introduced regression; restore correct EDU typing format.

## 0.5.9

- Establish `tests/conformance/` as the canonical home for Matrix v1.18 spec
  conformance tests; move 10 files from `tests/unit/`, add dedicated meson
  build target, update the registration validation script.
- Add `test_identifier_grammar.cpp` covering user IDs, localparts, event IDs,
  and server names per Appendices § Identifier Grammar.
- Add `test_signing_json_conformance.cpp` covering signing-payload field
  exclusion, canonical JSON serialisation, round-trip sign/verify, and
  signature-presence checks.
- Strengthen canonical JSON tests: add spec Example test vectors, integer-range
  boundary checks (surfaces 2^53 range spec violation), NUL-byte escape
  round-trip, control character escaping, and key Unicode code-point ordering.
- Three new conformance tests intentionally fail against the current
  implementation, identifying real spec violations to fix next.
- Restore the stable room-version policy registry for Matrix room versions
  `1` through `9`, with the spec-correct event-format, auth-rule,
  redaction-rule, and state-resolution selections used by version-aware event
  logic.
- Tighten inbound federation `PUT /_matrix/federation/v1/send/{txnId}` to the
  Matrix v1.18 transaction envelope: the body must now be a canonical-JSON
  object with `origin`, `origin_server_ts`, and a `pdus` array, while `edus`
  remains optional but must be an array when present.
- Accept empty federation transactions with `pdus: []` per the spec, while
  still routing each supplied PDU or EDU to the configured sink and returning
  per-PDU failures inside the response body.
- Return `403` rather than `502` for inbound federation request-signature
  mismatches and bad remote signatures so auth failures are surfaced as auth
  failures.
- Fix stale local conformance/unit coverage around Matrix v1.18 localpart and
  state-resolution behavior, and correct malformed `m.replace` / `m.thread`
  relationship test bodies so they exercise valid JSON requests.
- Second conformance pass: fix test accuracy bugs (255-byte boundary, 86-char
  signature, valid_until_ts range), add spec cryptographic test vectors
  (all pass — signing and base64 encoding confirmed correct), add redaction
  field-level conformance tests for v10 vs v11 rule differences, add room
  version auth-rule comparison tests. Six total conformance failures now
  pinpointing: canonical JSON integer range, NUL-byte parser bug, uppercase
  localpart rejection, and room versions 1–9 not implemented.

- Fix authenticated device binding for `GET /_matrix/client/v3/account/whoami`
  and all client key API routes. The server now resolves `device_id` from the
  bearer-token session instead of guessing from the account's first known
  device, which fixes registration-issued sessions and multi-device E2EE
  bootstrap.
- Add strict regressions for two live client paths that were previously
  uncovered: a post-registration session using `whoami` plus `/keys/upload`,
  and a multi-device account uploading keys from the second logged-in device.
- Add a strict end-to-end integration flow for the registration-shaped client
  path: registration-issued `access_token` plus `device_id`, `/keys/upload`,
  `/keys/query`, `/keys/claim`, invite/join bootstrap, `sendToDevice`
  `m.room_key`, encrypted room send, read receipt propagation, `/members`, and
  leave in one Matrix v1.18 user flow.

## 0.5.8

- Fix `GET /_matrix/client/v3/rooms/{roomId}/members` so it parses
  `membership` and `not_membership` exactly, decodes the room identifier
  correctly, and returns client-format `m.room.member` state events with
  `event_id` instead of an empty or malformed chunk when current state exists.
- Surface joined-room `m.receipt` and `m.typing` ephemerals in `/sync`, backed
  by per-entry sync stream IDs so incremental syncs deliver the updates Matrix
  clients expect during ordinary room use.
- Tighten `/keys/upload` and `/keys/query` interop by validating uploaded
  device-key identity against the authenticated session and normalizing returned
  local device bundles to authoritative `user_id`, `device_id`, and
  `ed25519:`/`curve25519:` key identifiers.
- Add strict regressions for stale-membership `/members`, incremental `/sync`
  receipts, device-key identity validation, and a client-shaped end-to-end
  integration flow covering login, invite/join, `keys/query`, `keys/claim`,
  `sendToDevice`, encrypted messaging, read receipts, and leave.

## 0.5.7

- Percent-decode `/_matrix/client/v3/user/{userId}/account_data/{type}` before
  persistence and lookup. Secret-storage descriptors such as
  `m.secret_storage.key.<key_id>` now survive percent-encoded path segments and
  round-trip correctly through `PUT`, `GET`, and `/sync account_data.events`.
- Add strict regressions for the secret-storage bootstrap path: the runtime
  suite now proves a percent-encoded secret-storage key type is surfaced back
  as the decoded Matrix event type in `/sync`, and the conformance suite
  asserts the encoded `PUT`/`GET` round-trip required by the Matrix v1.18
  client-server account-data endpoints.

## 0.5.6

- Report `device_one_time_keys_count.signed_curve25519 = 0` on `/sync` for
  fresh logged-in devices that have not uploaded any one-time keys yet. This
  gives Matrix clients an explicit bootstrap signal instead of an empty count
  object during E2EE startup.
- Add strict client-shaped coverage for local encrypted to-device delivery by
  asserting that `PUT /_matrix/client/v3/sendToDevice/m.room.encrypted/{txnId}`
  preserves the nested Olm ciphertext object through `/sync to_device.events`.
- Add a regression proving that a fresh device's `/sync`
  `device_one_time_keys_count` includes `signed_curve25519: 0` rather than
  omitting the algorithm entirely.

## 0.5.5

- Fix `GET /_matrix/client/v3/rooms/{roomId}/messages` returning raw stored
  event JSON without `event_id` in `chunk`. The endpoint now emits the same
  client-facing room-event format as `/sync`, so Matrix clients stop rejecting
  encrypted timeline events fetched through back-pagination or room history.
- Exempt browser `OPTIONS` preflight requests from the client-server rate
  limiter by handling them before bucket checks. Repeated preflights no longer
  consume the real route quota or trigger `429 M_LIMIT_EXCEEDED` on the actual
  login, room-history, or media-config request that follows.
- Add strict regressions for both interop failures: `/messages` now has a
  conformance assertion that every timeline and state event carries `event_id`,
  and the runtime suite now proves repeated browser preflights stay `200` and
  do not consume the target route's rate-limit bucket.
- Bump packaging and binary version metadata to `0.5.5` for the new branch and
  PR.

## 0.5.4

- Persist local invite metadata for locally-created rooms so invitees see a
  populated `rooms.invite.*.invite_state.events` payload in `/sync`, instead of
  an empty invite shell.
- Allow `POST /_matrix/client/v3/rooms/{roomId}/leave` to reject an invite as
  well as leave a joined room, matching the Matrix v1.18 membership flow.
- Persist a real `m.room.member` leave state event on local leaves so current
  room state, `/members`, and initial `/sync` stop reporting stale join or
  invite membership after the user leaves.
- Delete stale invite metadata when a user joins or leaves a room, including
  inbound federated membership transitions, so client-visible room classification
  no longer lags behind current membership.
- Replace the remaining membership-operation placeholder tests with strict
  Matrix v1.18 conformance scenarios for `invite`, `ban`, `kick`, `unban`,
  `forget`, and `knock`, asserting membership state transitions and `/sync`
  visibility instead of tolerating `404 M_UNRECOGNIZED`.
- Implement `POST /_matrix/client/v3/rooms/{roomId}/invite`, `/ban`, `/kick`,
  `/unban`, and `/forget`, plus `POST /_matrix/client/v3/knock/{roomIdOrAlias}`,
  so the strict membership conformance scenarios now exercise real room-member
  state transitions instead of missing endpoints.
- Publish `rooms.knock` entries from `/sync` and treat `forget` as a durable
  membership-row removal after `leave` or `ban`, matching the Matrix v1.18
  room-membership surfaces exercised by the new tests.
- Fix encrypted post-invite joins for real clients. When a user newly joins a
  room, `/sync` now includes the full current room state snapshot for that
  joined room, and `GET /rooms/{roomId}/messages` now includes current state
  instead of an always-empty `state` array. This restores `m.room.encryption`
  bootstrap for clients like Element and Cinny.
- Record device-list changes when room sharing starts or ends. Local and remote
  join/leave membership transitions now publish `device_lists.changed` and
  `device_lists.left` updates for local observers when they begin or stop
  sharing a room with another user, allowing clients to refresh device keys and
  deliver room keys after invite acceptance.
- Add end-to-end encrypted-room regressions for the actual failing path:
  device-list refresh on post-invite join, first joined-room `/sync` bootstrap,
  and `/messages` state bootstrap for encrypted rooms. These tests now fail if
  room membership works but E2EE setup still breaks.
- Extend the E2EE conformance coverage around post-invite room bootstrap. The
  suite now asserts the full local `keys/changes` -> `keys/query` ->
  `keys/claim` -> `sendToDevice` -> `/sync to_device.events` path, verifies
  that `sendToDevice` only reaches the addressed local device and drains once,
  and checks that `device_lists.left` is not emitted while users still share a
  different room.
- Align the packaging scripts and RPM spec with version `0.5.4` so the package
  workflow stops failing on stale `0.5.2` metadata after the branch version
  bump.

## 0.5.2

- Fix local invite-to-join membership transitions. Invited local users no
  longer count as joined in `LocalRoom.members` before a real
  `m.room.member` join event exists.
- Local joins now persist a fresh `m.room.member` state event with
  `content.membership = "join"`, so `GET /_matrix/client/v3/rooms/{roomId}/members`
  and `/sync` stop surfacing stale invite state after the invitee accepts.
- Runtime hydration now rebuilds `LocalRoom.members` from `join`
  memberships only, preventing the stale invite/member confusion from
  reappearing after restart.
- Add a conformance regression for invited local join state and tighten
  the non-invite local join test to use a `public_chat` room, matching
  Matrix v1.18 join-rule semantics.
- Fix the remaining conformance and complement join fixtures so success
  paths only join public rooms or invited private rooms, instead of
  depending on the old invite-only join bug.
- Keep `LocalRoom.members` aligned with joined membership only by
  ignoring `invite` and `knock` updates in the runtime projection,
  instead of treating them as removals.

## 0.5.1

- Wire the wall-clock rate-limit engine, per-module log-level
  overrides, and audit-routing helper into production.
- New `client_rate_limits.*` config keys (per-IP and per-user,
  keyed by target prefix, format `<N>/<Ws>s`).
- New `log_modules.*` config keys for per-module and wildcard
  default log levels. Restart required to take effect.
- `/_merovingian/admin/audit` accepts `?category=` and
  `?event_type=` query-string filters. Unknown categories
  return 400.
- Five high-signal failure call sites now route through
  `observability::log_diagnostic_audit`, which at severity
  `warning` or above appends a row to `audit_log` with the
  same actor / target / reason as the structured log line:
  `rate_limit.exceeded`, `login.rejected`,
  `access_token.rejected`, `request.rejected`,
  `registration_policy.denied`.
- New BDD tests: `tests/unit/test_config_client_rate_limits.cpp`
  (4 scenarios), `tests/unit/test_config_log_modules.cpp`
  (3 scenarios), `tests/unit/test_audit_filter.cpp`
  (2 scenarios), and a new SCENARIO in
  `tests/integration/test_client_server_flow.cpp` for the
  round-trip audit-filter request.
- New operator docs: `docs/log-filtering.md`.

## 0.5.0
- Add the wall-clock `RateLimitEngine<Clock>` template, the
  per-event severities on `SingleLog`, and the per-module
  `set_module_log_level` / `set_default_log_level` API.

## 0.4.62
- Fix `/keys/upload` accepting one-time and fallback keys whose signature is
  not made by the device's own ed25519 identity key. The Matrix v1.18 spec
  (§11.10.1.4) requires every SignedKey to be signed by the device's
  signing key; the server was storing any signature, so a stale device row
  (or a buggy client) could leave behind OTKs whose signature cannot be
  verified by the peer that claims them. matrix-rust-sdk then reports
  `NoSignatureFound` at `/keys/claim` time, refuses to establish the Olm
  session, and drops the sender's `m.room_key` to-device message. That was
  the live bug on pong.ping.me.uk: Element james could not decrypt Cinny
  jc2's `m.room.encrypted` messages, and the Element Web UI was stuck on
  `joining` for the room because the encrypted state events were
  unverifiable.
- The `/keys/upload` validator extracts the device's ed25519 signing key id
  from the in-body `device_keys` first, then from the persisted device_keys
  row, and rejects (400 `M_INVALID_SIGNATURE`) any OTK or fallback key
  whose embedded `signatures` map does not contain a signature by that key
  id. Non-SignedKey members (e.g. the legacy integer-count form, which
  the v1.18 spec no longer allows) are also rejected. When no device
  signing key is known yet the OTK is still accepted, so a device's very
  first `/keys/upload` is unaffected.
- Update the existing `E2EE device_keys round-trip` test to use a proper
  SignedKey for the OTK member; the previous legacy integer-count form
  is no longer valid in v1.18.
- New BDD coverage in `tests/unit/test_otk_signature_validation.cpp`:
  reject OTK signed by a different key (the bug reproducer), accept OTK
  signed by the device's own key, reject fallback key signed by a
  different key, and accept a first-time OTK upload before device_keys
  is known.

# Changelog

## 0.4.61
- Fix `POST /_matrix/client/v3/login` defaulting `device_id` to the
  literal string `"MEROVINGIAN"` when the client omits it from the
  request body. Matrix v1.18 §5.3.2 requires the server to mint a
  unique opaque id in that case; the literal caused every
  device-id-less login to collide on a single shared device row, so
  two users (or two device-id-less devices of the same user) shared
  one `device_keys` upload slot and E2EE key bundles pointed at the
  wrong identity key. The server now generates a fresh 128-bit
  hex `device_id` per login when the body does not include one, and
  the new "Login without device_id generates a unique opaque id"
  BDD scenario guards the fix.
- Make the E2EE key bundle round-trip through `keys/upload` and
  `keys/query`. After this build, a device that uploads its
  `device_keys`, `one_time_keys`, and `fallback_keys` is queryable by
  other users in shared rooms, with uploaded signatures merged back
  into the response. Element's "No key bundle found for user" log
  no longer appears once the inviter has completed a single
  `keys/upload` round-trip.
- Persist `device_keys`, `one_time_keys`, and `fallback_keys` to the
  existing `persistent_store` (PostgreSQL + SQLite) rather than the
  in-memory `key_api_records` audit vector; restart-safe.
- Return the spec-shaped response body for `keys/upload`
  (`one_time_key_counts` populated with `signed_curve25519` etc.) and
  `keys/query` (`device_keys` + `master_keys` + `self_signing_keys` +
  `user_signing_keys`), matching what Element expects when validating
  an inviter's cross-signing keys.

## 0.4.60
- Merovingian now emits the `Access-Control-Allow-*` response headers
  itself, so a vanilla reverse proxy that does not synthesize CORS
  headers stops breaking browser clients (Element desktop, etc.) on
  every cross-origin request. The preflight `OPTIONS` short-circuit
  returns `200` with `Access-Control-Allow-Origin`,
  `Access-Control-Allow-Methods`,
  `Access-Control-Allow-Headers`, `Access-Control-Max-Age`, and
  `Vary: Origin`, and the same headers are attached to every other
  response (so the actual request also passes the browser's
  post-preflight CORS check).
- New `server.cors.*` config keys: `allowed_origins` (default `*`,
  which is safe for Matrix because clients use bearer tokens, not
  browser-credentialed cookies), `max_age` (default 86400),
  `allow_credentials` (default `false`),
  `allow_methods` (default
  `GET, POST, PUT, DELETE, OPTIONS`), and `allow_headers` (default
  `authorization, content-type`).
- Reject `server.cors.allow_credentials=true` combined with a wildcard
  origin in `allowed_origins`, which the CORS spec forbids. CORS is
  read at startup; a config change still requires a server restart
  to take effect.
- `docs/configuration.md` "Reverse proxy examples" rewritten with
  copy-pasteable configs for nginx, Apache, Caddy, Traefik, HAProxy,
  and Cloudflare. Each example notes that no `Access-Control-*`
  configuration is required because Merovingian emits them, and
  includes a `curl` smoke test for the preflight.

## 0.4.59
- Fix canonical-JSON integer parsing to reject leading zeros and explicit
  positive signs per Matrix canonical-JSON spec. `01`, `007`, and `+5` are
  now `invalid_number`; only `^-?(0|[1-9][0-9]*)$` is accepted as a
  canonical int64. The parser also returns `unexpected_token` (not
  `invalid_number`) when yyjson yields no raw data for a number position,
  matching spec wording.
- Pass `YYJSON_READ_STOP_WHEN_DONE` to yyjson so the adapter stops reading
  at the end of the top-level value, rejecting trailing-garbage payloads
  per canonical-JSON.
- Surface the exception type and message when the thread-pool worker
  catch-all swallows an exception, and at the three corresponding
  swallowed-exception sites in `http_server`. Log fields `type` (from
  `abi::__cxa_current_exception_type()->name()`) and `what` (from
  `std::exception::what()`) are now attached to every swallowed-exception
  log line. Includes a portability fallback when `<cxxabi.h>` is absent.
- Switch the `schema_migrations` INSERT in `sqlite_store` from string
  concatenation to a `PreparedStatement` with bound parameters, matching
  the `persistent_store.cpp` pattern. Migration descriptions containing
  quotes or NUL bytes now round-trip safely.
- Document the `thread_pool::request_stop` non-reentrancy contract and
  guard it with a debug-only assertion. Document the
  `sqlite_transient_destructor` lifetime contract in `sqlite_store.cpp`
  so a future refactor does not silently switch to `SQLITE_STATIC` and
  corrupt binds.

## 0.4.58
- Fix registration UIAuth incomplete-credentials conformance. Per Matrix v1.18
  §5.5.1, when a client submits `POST /register` with an `auth` dict that is
  present but incomplete (missing `token` for `m.login.registration_token` or
  using an unsupported `auth.type`), the homeserver must return `401` with the
  UIA challenge — not proceed to registration and fail with `403 M_FORBIDDEN`.
  Merovingian now validates `auth.type` and the required `token` parameter before
  accepting the registration, so clients in the UIA flow receive the correct
  challenge response and can retry with the token.

## 0.4.57
- Tighten Matrix v1.18 `/sync` conformance coverage. The client-server
  conformance suite now asserts the full top-level `/sync` envelope
  (`rooms`, `presence`, `account_data`, `to_device`, `device_lists`,
  `device_one_time_keys_count`, and `device_unused_fallback_key_types`)
  as well as the joined/invited/left room category object shapes.
- Fix the `/sync` room envelope to always include `rooms.knock`, matching the
  v1.18 response shape even when the homeserver has no knocked rooms to report.
- Implement the remaining Matrix v1.18 registration discovery and validation
  routes. `GET /_matrix/client/v3/register/available` now reports availability
  with `M_USER_IN_USE` and `M_INVALID_USERNAME` rejections, and
  `GET /_matrix/client/v1/register/m.login.registration_token/validity` now
  reports whether the configured registration token is usable.
- Implement homeserver-managed registration validation sessions for
  `POST /_matrix/client/v3/register/email/requestToken` and
  `POST /_matrix/client/v3/register/msisdn/requestToken`. Both routes now
  accept spec-shaped request bodies and return opaque `sid` values, with
  repeat requests for the same validation triple reusing the same session.
- Tighten `POST /_matrix/client/v3/register` error conformance by rejecting
  invalid localparts with `M_INVALID_USERNAME` before attempting account
  creation.
- Fix Matrix registration UIA probing for empty JSON bodies. Matrix clients
  often begin account creation with `POST /_matrix/client/v3/register` and an
  empty `{}` body to discover the required interactive-auth stages. Merovingian
  was validating `username` and `password` first and incorrectly returning
  `400 M_BAD_JSON`; it now returns the expected `401` UIA challenge with
  `flows`, `params`, and `session`.
- Fix Matrix v1.18 push-rule discovery for authenticated clients. Merovingian
  now returns the spec-defined server-default ruleset from
  `GET /_matrix/client/v3/pushrules/`, exposes the same ruleset through
  `GET /_matrix/client/v3/pushrules/global/`, and serves built-in rule lookups
  plus their `actions` and `enabled` views for the implemented GET endpoints.
- Fix stable unauthenticated OIDC discovery probing.
  `GET /_matrix/client/v1/auth_metadata` now returns the same pre-auth
  `404 M_UNRECOGNIZED` as the unsupported MSC2965 discovery namespace instead
  of falling through to the access-token gate and producing a misleading `401`.
- Fix outbound federation transaction IDs for E2EE to-device delivery.
  Merovingian was deriving `/send/{txnId}` from the local `next_session_id`
  counter, which resets on restart. That let a fresh `m.direct_to_device` EDU
  reuse an older transaction ID and be deduplicated by the remote homeserver as
  a replay. Federation transaction IDs are now generated independently of local
  session state, and `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`
  now preserves the client `{txnId}` as the outbound EDU `message_id`.
- Fix federated `GET /_matrix/federation/v1/query/profile` for existing local
  users missing a stored profile row. The route now returns a spec-shaped empty
  profile object for a known local user instead of treating the absent
  `profiles` row as "user not found". Added signed-route regression coverage for
  the full `X-Matrix` path through `handle_federation_http_request`.
- Fix inbound federated `m.direct_to_device` parsing for encrypted payloads.
  Merovingian previously scanned the EDU content with raw brace searches in
  `local_http_router.cpp`, which broke nested encrypted payloads and multi-device
  target maps. Federated to-device messages now traverse canonical JSON instead,
  preserving the full per-device payload that `/sync` must expose in
  `to_device.events`.

## 0.4.55
- Fix Matrix v1.18 fallback-key claim semantics for E2EE session setup.
  `POST /_matrix/federation/v1/user/keys/claim` now returns a matching fallback
  key when no one-time key remains, instead of incorrectly returning no key at
  all. This aligns the federation responder with the v1.18 requirement that
  fallback keys are reused until replaced.
- Fix fallback-key lookup to match the requested algorithm. Merovingian
  previously returned no key if the first stored fallback for a device used a
  different algorithm, even when a later matching fallback key existed. Client
  `POST /_matrix/client/v3/keys/claim` and federated claims now both select the
  correct fallback key.
- Fix Matrix v1.18 signature publication and room-level key-backup behavior.
  Uploaded signatures from `POST /_matrix/client/v3/keys/signatures/upload`
  now appear in subsequent `POST /_matrix/client/v3/keys/query` responses for
  both device keys and cross-signing keys. Room-level backup routes
  `PUT /_matrix/client/v3/room_keys/keys/{roomId}` and
  `DELETE /_matrix/client/v3/room_keys/keys/{roomId}` now persist and remove
  only the targeted room's sessions instead of failing with a 500 path.
- Add Matrix v1.18 conformance coverage for the remaining encryption/signing
  endpoints on this surface: `POST /keys/device_signing/upload`,
  `POST /keys/signatures/upload`, room-level `GET`/`PUT`/`DELETE /room_keys/keys/{roomId}`,
  signed federation `POST /_matrix/federation/v1/user/keys/query`,
  `POST /_matrix/federation/v1/user/keys/claim`,
  `GET /_matrix/federation/v1/user/devices/{userId}`, and
  `GET /_matrix/key/v2/server`.
- Add regression coverage for both client-server and federation key-claim
  paths, including mixed fallback-key algorithms and fallback-key reuse.
- Add federated E2EE delivery coverage for inbound `m.direct_to_device`:
  nested encrypted payloads now have a conformance test that reaches
  `/sync to_device.events`, and a second test verifies one federated EDU can
  fan out to multiple local target devices without dropping later entries.

## 0.4.54
- Fix Matrix v1.18 room-key backup metadata and update responses. Merovingian
  was returning incomplete JSON for key-backup metadata and key-storage update
  requests: `GET /_matrix/client/v3/room_keys/version` and
  `GET /_matrix/client/v3/room_keys/version/{version}` omitted the required
  `count` and `etag` fields, while `PUT /_matrix/client/v3/room_keys/keys` and
  `PUT /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}` incorrectly
  returned `{"version":"1"}` instead of `RoomKeysUpdateResponse`. Element's
  Rust crypto SDK rejected those responses during backup processing with
  `missing field etag`. Merovingian now computes backup session `count`, derives
  an opaque `etag` from the stored backup contents, includes both fields in the
  metadata endpoints, and returns `{"count", "etag"}` for room-key backup
  writes and deletes.
- Fix `DELETE /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}`. The
  route returned 200 but did not delete the stored backup session, so the new
  `count` metadata would have remained stale and clients could still fetch the
  supposedly deleted session.
- Add Matrix v1.18 conformance coverage for key-backup metadata and update
  responses: `GET /room_keys/version`, `GET /room_keys/version/{version}`,
  batch `PUT /room_keys/keys`, direct `PUT /room_keys/keys/{roomId}/{sessionId}`,
  direct `DELETE /room_keys/keys/{roomId}/{sessionId}`, and an overwrite
  regression that proves `etag` changes when a session is updated without
  changing the total key count.

## 0.4.53
- Fix key-backup session lookup for percent-encoded Matrix path components.
  Real Megolm session IDs can contain `/`, so clients encode the
  `/{roomId}/{sessionId}` path as `%21room.../DDY%2F...` when calling
  `GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}?version=1`.
  Merovingian was storing batch-uploaded sessions under the decoded JSON
  session ID but looking them up using the still-encoded path fragment, which
  produced 404 `M_NOT_FOUND` immediately after a successful backup upload and
  caused clients to keep retrying key backup/recovery during E2EE setup. Room
  key backup path parsing now decodes `room_id` and `session_id` consistently
  for direct PUTs and GETs, and a conformance regression series now covers the
  v1.18 batch-PUT -> encoded room-level GET, batch-PUT -> encoded session-level
  GET, and direct encoded PUT -> GET round-trips.

## 0.4.52

- Fix a data race in the federation outbound HTTP client that intermittently
  broke E2EE. `OutboundClient` reused a single libcurl easy handle for every
  request, but the runtime shares one instance across the federation dispatch
  worker thread and the HTTP request-handler thread pool. A libcurl easy handle
  must never be driven by more than one thread at a time, so concurrent calls
  (e.g. a client `/keys/query` federation proxy while the dispatch worker was
  sending a transaction to the same peer) corrupted the handle and surfaced as a
  spurious `network_error` returned in zero milliseconds. The failed remote key
  query returned an empty `device_keys` set, so the client could not establish
  Olm sessions with the remote devices and emitted `m.room_key.withheld`.
  `perform()` now drives a per-thread easy handle (created lazily, freed at
  thread exit), making a single `OutboundClient` safe to share across threads
  while preserving per-thread connection and TLS-session reuse. `OutboundClient`
  is now stateless (the per-instance pimpl was removed).
- Add a ThreadSanitizer (`tsan`) job to the sanitizers CI workflow. The existing
  sanitizer job only ran ASan+UBSan, neither of which detects data races, so the
  `OutboundClient` race above could not have been caught by CI. The new job
  builds and tests with `-Db_sanitize=thread` and uses a project suppressions
  file (`tests/sanitizer/tsan.supp`) scoped to third-party dependencies only.
  The new concurrency test in `tests/unit/test_outbound_client.cpp` is a
  deterministic regression guard under this job.
- Add a workflow tooling guard for the sanitizer matrix. The Python workflow
  tests now assert that `.github/workflows/sanitizers.yml` retains both the
  existing `asan-ubsan` job and the new `tsan` job wired to
  `tests/sanitizer/tsan.supp`, so a future CI edit cannot silently drop the
  race-detection coverage.
- Fix the unified `build.py` WSL entrypoint so it can execute sanitizer builds
  directly. Previously `python build.py wsl` ignored `--profile`, `--buildtype`,
  `--sanitize`, `--coverage`, `--build-fuzz`, and `--hardening`, and the
  `scripts/build-wsl.sh` wrapper could not parse those options either. WSL now
  exposes the same profile/sanitizer controls as the Linux and BSD targets, so
  `python build.py wsl --builddir build-tsan --buildtype debug --sanitize thread`
  and `python build.py wsl --builddir build-asan --buildtype debug --sanitize address,undefined`
  are first-class supported paths. Added tooling coverage and updated the
  developer docs.

## 0.4.51

- Fix `m.receipt` federation EDU content format: the receipt content was built
  as `{roomId:{userId:{event_ids,ts}}}` but the Matrix spec requires
  `{roomId:{receiptType:{userId:{event_ids,data:{ts}}}}}`. The missing
  receipt-type nesting level and the `ts` being outside `data` caused Synapse to
  return HTTP 500 "Error handing EDU of type m.receipt" for every outbound
  transaction carrying a receipt EDU, opening the circuit breaker and blocking
  all subsequent federation including to-device key-exchange messages (breaking
  E2EE). Fix extracts a pure `build_receipt_edu_content` helper in
  `outbound_transaction.cpp` used by both the `/receipt/` and `/read_markers`
  endpoints.

## 0.4.50

- Implement `GET /room_keys/version/{version}`: returns backup metadata for the
  requested version, or 404 M_NOT_FOUND if absent.
- Implement `GET /room_keys/keys` (bulk): returns all sessions grouped as
  `{"rooms":{"roomId":{"sessions":{...}}}}`.
- Implement `DELETE /room_keys/keys` (bulk): removes all key backup sessions
  via `delete_all_key_backup_sessions`, returns `{"count":0,"etag":"1"}`.
- Fix `GET /room_keys/keys/{roomId}` response format: was returning
  `{"rooms":{}}` (wrong per spec); now returns `{"sessions":{sessionId:data,...}}`.
- Add round-trip conformance tests: keys/upload→query, keys/upload OTK→claim
  (OTK consumed), batch PUT→GET bulk (rooms structure), batch PUT→GET/{roomId}
  (sessions structure), bulk DELETE→GET confirms empty.
- Fix key backup routing: `PUT /room_keys/keys?version=N` was returning 404
  because `match_key_api_route` compared the path template against the full
  request target including the query string. The fix strips the query portion
  before the exact-match comparison so real client requests reach the handler.
- Fix `PUT /room_keys/keys/{roomId}/{sessionId}`: query string (`?version=N`)
  was included in the stored `session_id`, making subsequent GETs unable to find
  the session.
- Fix `GET /room_keys/keys/{roomId}/{sessionId}`: was returning a hardcoded
  `{"rooms":{}}` stub instead of the stored `KeyBackupData`. The handler now
  looks up the session in `persistent_store.key_backup_sessions` and returns 404
  M_NOT_FOUND when the session does not exist. Room-level GETs
  (`/{roomId}` with no session component) continue to return the existing stub.
- Add conformance tests: GET returns stored session fields, GET 404 for unknown
  session, PUT with `?version` query param routes correctly.

- Fix `send_join` response to return room state **prior to** the new join event,
  per spec §11.5.1. Previously we persisted the join event first then built state
  from the live store, so the joining user appeared as `membership=join` in the
  state snapshot. Synapse uses the returned state to recalculate expected
  `auth_events` for the join — finding the join event itself as the member state
  creates a circular reference that triggers a Synapse WARNING and causes
  `auth_events` mismatch errors. The fix snapshots state IDs before persistence
  and uses that pre-join snapshot for both `state` and `auth_chain` in the
  response. Updated the existing `send_join` state test (which had the spec
  backwards: was asserting `membership=join`, now correctly asserts
  `membership=invite`) and added an assertion that the join event ID itself is
  absent from the returned state array.

## 0.4.49

- Fix `make_join` template including `m.room.create` in `auth_events` for room
  version 12. In room v12 (MSC4291) the room ID is the reference hash of the
  create event, so the create event is implicit and must never appear in any
  event's `auth_events`. Synapse asserts this and returns 500 to its joining
  client even though `send_join` returned 200. Gated via
  `RoomVersionPolicy::create_event_is_room_id`.
- Fix `POST /register` to return `access_token` and `device_id` in the 200
  response when `inhibit_login` is absent or false, as required by spec §5.5.1.
  Previously only `user_id` was returned; clients that relied on the registration
  token (e.g. Element) had to call `/login` immediately after registration.
- Fix `401` responses for requests with no bearer token to return errcode
  `M_MISSING_TOKEN` instead of `M_UNKNOWN_TOKEN`, as required by spec §5.7.2.
  `M_UNKNOWN_TOKEN` now applies only when a token is present but unrecognised.
- Strengthen spec conformance test coverage across five test files:
  - `test_federation_invite_join`: replace `body.find()` substring checks with
    parsed JSON navigation; add exact `depth = max(extremity) + 1` assertion;
    add six new scenarios covering `room_version`, all event template fields,
    `auth_events` completeness (`power_levels` + `join_rules` + invite, no
    create), 404 for unknown room, 400 `M_INCOMPATIBLE_ROOM_VERSION`, and
    `send_join` `origin`/`state`/`auth_chain` field validation.
  - `test_client_server_conformance`: promote `access_token`/`device_id` checks
    in register from comments to `REQUIRE`; add `body.empty()` to logout and
    `keys/device_signing/upload`; add `user_id` value equality in whoami;
    tighten 401 errcode to `M_MISSING_TOKEN`.
  - `test_federation_conformance`: replace all `body.find()` in `make_join` and
    `send_join` THEN blocks with JSON-parsed field checks.
  - `test_federation_key_query`: full rewrite — all assertions were substring
    matches; now navigate `device_keys`, `master_keys`, `self_signing_keys`,
    `one_time_keys` by JSON key and verify `user_id` equality and array sizes.
  - Integration tests updated to reflect the new register behaviour (two devices
    and two tokens after register + login, one token revoked by logout).

## 0.4.48

- Fix federated join so Synapse users can successfully join rooms hosted on
  Merovingian. Three bugs caused Synapse to return `500 Internal Server Error`
  to its joining client, producing an infinite `make_join`/`send_join` retry loop:
  - `send_join` v2 response was missing the required `members_omitted` field.
    Synapse raises a `KeyError` parsing `SendJoinResponse` without it.
  - `make_join` template had `depth=0` (field was never set). Synapse used this
    value verbatim, producing join events at depth 0 that fail state resolution.
  - `make_join` template `prev_events` contained all room events instead of only
    the forward extremities, inflating the state snapshot on every retry.

## 0.4.47

- Fix federated invite-join flow so remote homeservers (e.g. Synapse) no longer
  reject joins with `403: You are not invited to this room`. Three bugs fixed:
  - `membership_template_provider` now populates `auth_events` in the `make_join`
    template with `m.room.create`, `m.room.join_rules`, `m.room.power_levels`,
    and the joining user's current membership event (invite). Without this, the
    joining server signed a PDU with empty `auth_events`.
  - `membership_acceptor` now copies `auth_event_ids` from the inbound PDU
    envelope to the persisted `PersistentEvent`, enabling the BFS auth-chain walk
    to follow links and include referenced events in the `send_join` response.
  - `invite_handler` now stores inbound invite events in `store.events` and
    `store.state` so they are reachable during auth-chain construction for the
    case where a remote server invites one of our local users.

## 0.4.46

- Fix PDU dispatch to include invited users in `room->members` so federated
  events are delivered to invited users' home servers. Previously, only "join"
  members were added at runtime, causing invitees' servers to never receive
  room events.
- Fix `apply_runtime_membership` to handle "invite" (add) and "ban" (remove)
  membership transitions, not just "join"/"leave".
- Fix runtime startup to filter `room->members` to only "join" and "invite"
  memberships, consistent with runtime behavior.
- Add receipt endpoint `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}`
  per Matrix spec v1.18 §receipts. Previously only `/read_markers` was handled.
- Add user directory search endpoint `POST /_matrix/client/v3/user_directory/search`
  per Matrix spec v1.18. Returns matching profiles from the local user directory.
- Add media thumbnail endpoints `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}`
  and `GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}` per
  Matrix spec v1.18. Returns 64x64 thumbnails for locally stored media.
- Add key backup batch PUT endpoint `PUT /_matrix/client/v3/room_keys/keys`
  per Matrix spec v1.18. Previously only per-session PUT was supported.
- Add v1 media download endpoint `GET /_matrix/client/v1/media/download/{serverName}/{mediaId}`
  (authenticated variant) per Matrix spec v1.18.
- Enhance spec conformance tests with positive (success) verification for receipt,
  user directory search, key backup batch PUT, media upload, media download (v3/v1),
  and media thumbnail (v3/v1) endpoints. Tests now verify correct response data,
  not just that routes are recognized or return 404 for missing resources.

## 0.4.45

- Fix `auth_events` to include only the events required by the Matrix spec for
  each event type, instead of all room state events. Synapse rejects events
  that list unrelated auth events (e.g. `m.room.join_rules` in a
  `m.room.history_visibility` event's `auth_events`) with "unexpected
  auth_event for ('m.room.join_rules', '')", which cascaded into broken
  invite state and "You are not invited" join failures for federated users.
  Non-member events now include only `m.room.create` + `m.room.power_levels`
  + the sender's `m.room.member`; member events additionally include
  `m.room.join_rules` and the target's `m.room.member` per spec v1.18.
- Deduplicate `createRoom` preset events when the client already provides
  them in `initial_state`. Previously, including `m.room.guest_access`,
  `m.room.join_rules`, or `m.room.history_visibility` in `initial_state`
  produced duplicate state events. Now the preset emission is skipped for any
  event type the client supplies, matching the existing `m.room.encryption`
  dedup pattern.

## 0.4.44

- Fix room version 12 (MSC4291) room creation so the creator and any
  `additional_creators` are omitted from `m.room.power_levels` `content.users`.
  In v12 creators hold an implicit, infinite power level and must not be listed
  explicitly; Synapse (and the v12 auth rules) reject a power_levels event that
  names a creator with `Creator user ... must not appear in content.users`, which
  prevented remote users from joining locally-created v12 rooms (including DMs).
  Any creator supplied via `power_level_content_override` is also stripped.
  Pre-v12 rooms are unchanged: the creator stays listed at power level 100.
- Make `createRoom` populate `additional_creators` per the spec (MSC4289, Matrix
  v1.16). For the `trusted_private_chat` preset in room version 12+, the server
  now **combines** the `additional_creators` supplied in `creation_content` with
  the `invite` array and **deduplicates** between them (the sender is already a
  creator and is never repeated), instead of overwriting `additional_creators`
  with the invite list and discarding any the client supplied. The field is only
  emitted for room versions that privilege creators; pre-v12 `trusted_private_chat`
  rooms continue to grant invitees power level 100 via `m.room.power_levels`.
- Fix outbound federation EDUs (typing, receipts, presence, to-device) to key
  each EDU by `edu_type` rather than `type`, as required by the federation spec.
  Synapse reads `edu["edu_type"]` and raised `KeyError: 'edu_type'`, returning
  HTTP 500 for the entire `/send` transaction — silently dropping all federated
  ephemeral and to-device traffic. The EDU transaction body is now built by a
  shared, unit-tested `federation::build_edu_transaction_body` helper.

## 0.4.43

- Support joining a remote room version 12 room (MSC4291). A v12 room ID is a
  bare reference hash of the create event with no `:server` suffix, so the
  resident server cannot be derived from the room ID. `POST /join/{roomIdOrAlias}`
  now parses the `server_name` and `via` (MSC4156) query parameters and attempts
  `make_join`/`send_join` against each candidate server in turn. For room versions
  10 and 11 the room ID's server domain is still used as a fallback candidate. A
  join request with no routable candidate server now returns a clear error instead
  of being treated as an unknown local room.

## 0.4.42

- Fix `send_join` `auth_chain` to walk the auth-events graph from current state
  instead of dumping all room events. Previously the `membership_acceptor`
  included every event in the room (including non-state events like
  `m.room.encrypted` and `m.room.message`) in the `auth_chain` response.
  Synapse assumes all auth_chain entries have `state_key` and crashes with
  `AttributeError: 'FrozenEventV4' has no 'state_key' property` when it
  encounters a message event, causing remote joins to fail with 502.
- Document `build.py` as the recommended build entry point in README,
  `docs/getting-started.md`, and `docs/dev-environment.md`.

## 0.4.41

- Add unified `build.py` script providing a single CLI entry point for Linux, BSD,
  and WSL builds. Delegates to existing shell scripts in `scripts/` and replaces
  `build-wsl.ps1` for WSL builds.

## 0.4.40

- Accept v12 (MSC4291) room IDs in event validation. The `matrix_id_is_valid`
  function required a `:` in all Matrix IDs, but MSC4291 room IDs are
  `!` + base64 hash without a `:server` suffix, causing `send_join` to fail
  with "invalid room_id" (400 Bad Request).

## 0.4.39

- Implement Matrix room version 12 (MSC4291 + MSC4289), fixing federation with
  Synapse. Previously the server advertised and defaulted to room v12 but built
  v12 rooms like v11, so a Synapse user's `send_join` failed signature
  verification on the `m.room.create` event ("Invalid signature … with key
  ed25519:… BadSignatureError") and could not join or exchange messages.
  - MSC4291: the room ID is now `!` + the reference hash of the `m.room.create`
    event (with no `:server` domain), the create event no longer carries a
    `room_id`, and the create event is excluded from every event's `auth_events`
    (it is implied by the room ID). Event redaction now drops `room_id` from the
    create event under v12 so the reference hash and signing payload match a
    conformant peer byte-for-byte. Room versions 10 and 11 are unchanged
    (server-scoped IDs, `room_id` in the create event, create event in
    `auth_events`).
  - MSC4289: the `m.room.create` sender and every user listed in the create
    event's `content.additional_creators` are room creators with an effectively
    infinite power level that outranks any integer power level and cannot be
    demoted via `m.room.power_levels` by a non-creator. Only room version 12
    privileges creators.
- Add spec-conformance tests covering room versions 10, 11, and 12 for the new
  behaviour: create-event redaction of `room_id`, room-ID derivation, exclusion
  of the create event from `auth_events`, creator power privilege, and the
  room-version policy flags. Existing power-level rejection tests were corrected
  to use a non-creator actor (a v12 creator now holds infinite power by spec).

## 0.4.38

- Add comprehensive spec-conformance tests for the federation event signing
  pipeline (signing payload, canonical JSON, redaction, content hash, event ID)
  covering room versions 10, 11, and 12. Tests verify byte-for-byte match
  against the Matrix v1.18 specification's expected output for each room version,
  catching regressions that would cause BadSignatureError on federation peers.
- Add Matrix v1.18 canonical JSON spec test vectors (key sorting, Unicode
  normalisation, null, integer representation) to the conformance test suite.
- Add spec event signing test vectors verifying that v1-v2 payloads preserve
  origin while v11+ payloads strip it, and that content redaction follows the
  correct room-version-specific rules.
- Add content hash and reference hash base64 encoding tests confirming the
  hashes.sha256 field uses standard unpadded Base64 (RFC 4648) and event IDs
  use URL-safe unpadded Base64, as required by the spec.

## 0.4.37

- Fix rooms created with private_chat or trusted_private_chat preset not
  enabling end-to-end encryption — Element reported "Encryption is not set up"
  because no m.room.encryption state event was emitted during room creation.
  The server now auto-emits m.room.encryption with the m.megolm.v1.aes-sha2
  algorithm for private presets, matching the Matrix spec recommendation. If the
  client already includes m.room.encryption in initial_state it is not
  duplicated.
- Implement PUT /sendToDevice/{eventType}/{txnId} — accepts Olm pre-key
  messages (m.room_key, m.olm.v1.curve25519-aes-sha2 key exchanges) and
  enqueues them for delivery via /sync to_device.events. This was a 404 gap
  that blocked all E2EE session establishment.
- Implement GET /keys/changes — returns users whose device lists changed
  between two /sync stream positions. Element calls this on startup to
  detect stale key caches. Uses sync::decode_stream_token to extract the
  correct sync_stream_id component from the composite next_batch token.
- Implement POST /keys/query federation proxying — remote users (server !=
  local) are grouped by home server and queried via
  POST /_matrix/federation/v1/user/keys/query. Unreachable servers are
  reported in the failures object. Uses perform_sync_outbound_call moved
  from room_service anonymous namespace to homeserver:: so both services
  can use it.
- Implement POST /keys/claim federation proxying — remote OTK claims are
  proxied to /_matrix/federation/v1/user/keys/claim on the target server.
- Implement sendToDevice remote delivery — messages targeted at users on
  remote servers are dispatched as m.direct_to_device EDUs via the
  federation transaction system (dispatch_edu_to_server helper). The
  inbound m.direct_to_device handler in local_http_router.cpp was already
  implemented; no change needed there.
- Add E2EE round-trip conformance tests: keys/upload → keys/query returns
  stored device keys; keys/upload → keys/claim returns and consumes OTKs;
  sendToDevice → /sync to_device.events delivers the message; keys/changes
  reflects key uploads that happen after the from token. These gaps meant
  E2EE regressions could not be caught by CI.
- Implement GET /rooms/{roomId}/state/{eventType}/{stateKey} — returns the
  content object of the named state event (404 M_NOT_FOUND if absent). This
  was an implementation gap; clients and conformance tests now use it to verify
  room state directly from the API.
- Add conformance tests for createRoom encryption: the conformance suite now
  asserts that private_chat and trusted_private_chat presets produce an
  m.room.encryption state event, and public rooms do not. This gap meant the
  encryption regression had to be reported rather than caught by CI.
- Fix .clangd indentation: YAML does not permit tab characters; converted all
  indentation to spaces so clangd parses the config correctly and the
  pp_file_not_found/no_member suppressions actually take effect.
- Add enhanced diagnostic logging to the event signing pipeline — the
  sign_event.accepted diagnostic now includes the exact signing payload,
  signature, and signed JSON to aid triage of federation BadSignatureError
  rejections.

## 0.4.36

- Fix /sync returning incomplete timeline events (only event_id and sender) —
  events now include full content (type, content, sender, event_id,
  origin_server_ts, state_key) so clients can render messages and determine
  room version from the m.room.create event
- Fix /sync state section returning only member_count instead of actual state
  events — initial sync now includes the full current room state (m.room.create,
  m.room.member, m.room.power_levels, etc.)
- Fix room_version_for_room fallback returning "10" instead of "12" when
  composing the first event in a new room, matching the createRoom and
  capabilities endpoint defaults
- Fix incorrect E2EE security assertions in run_client_server_flow and tests
  that rejected m.room.encrypted events in /sync output — the server correctly
  relays encrypted events opaquely for client-side decryption

## 0.4.35

- Add ccache compiler caching to GitHub Actions CI, package, and release workflows
  to speed up builds. Linux, Fedora, Alpine, and Debian container jobs now cache
  compiler output across runs; FreeBSD VM jobs are excluded due to VM action
  limitations.

## 0.4.34

- Add GET /account/3pid returning `{"threepids":[]}` so Element can load account settings
- Add GET /pushers returning `{"pushers":[]}` so Element can load notification settings
- Fix GET /rooms/{roomId}/members returning empty chunk for members without a
  persisted m.room.member state event — the handler now synthesizes a fallback
  event from the membership record when no state event is found
- Fix outbound federation invite signature verification failure — the signing
  payload now uses the pruned (redacted) event form matching Synapse's
  `compute_event_signature` behavior, which strips non-essential content
  fields like `is_direct` from m.room.member events before signing

## 0.4.33

- Add comprehensive Matrix v1.18 Client-Server API conformance test suite
  covering all 165 spec operations (221 test scenarios). Implemented endpoints
  verify 200 response shapes and required fields; gap endpoints document the
  current 404 M_UNRECOGNIZED response with clear IMPLEMENTATION GAP comments.

## 0.4.32

- Fix `DELETE /_matrix/client/v3/room_keys/version/{version}` not removing the
  key backup from the database. The handler returned 200 without touching storage,
  so the subsequent `GET /room_keys/version` still returned backup data. Element
  interpreted this as a failed delete and retried indefinitely in a tight loop.
  Added `delete_key_backup_version` to the database layer and wired it up; the
  delete is idempotent (missing version returns 200).

## 0.4.31

- Fix `POST /_matrix/client/v3/room_keys/version` returning `{}` instead of
  `{"version":"1"}`. The Matrix spec requires the response to include the
  version identifier of the newly created backup so clients can reference it.
  Element was failing with "Unable to set up keys" because it could not read
  the backup version from the empty response body.

## 0.4.30

- Fix federation join state events stored with `stream_ordering == 0`, making
  them invisible to incremental `/sync`. After a user joined a remote room via
  the make_join/send_join handshake, the state and auth chain events from the
  send_join response were persisted via `store_event()` with the default
  `stream_ordering` of `0`. Since incremental sync filters out events where
  `stream_ordering <= since_ordering`, and `0 <= any_since_ordering` is always
  true, these events were never returned. Combined with the incremental sync
  suppression that omits rooms with empty timeline and account data, the
  joined room was completely absent from the sync response. The fix assigns
  proper stream ordering from `next_stream_ordering++`, parses `depth`,
  `prev_event_ids`, and `auth_event_ids` from the event JSON, creates
  `PersistentStateEvent` entries for state events, and calls
  `store_event_with_state()` instead of `store_event()`.
- Fix cross-signing key upload (`POST /keys/device_signing/upload`) only storing
  the `master` key type, losing `self_signing` and `user_signing` keys. The
  handler now parses the request body and stores each key type individually.
  The `keys/query` response now includes `master_keys`, `self_signing_keys`,
  and `user_signing_keys` sections, fixing Element's "Unable to set up keys"
  error during E2EE cross-signing setup.

## 0.4.29

- Fix make_join validation rejecting event templates that omit the `origin` field.
  The `origin` field was removed from events starting in room version 4 (which
  introduced hash-based event IDs replacing server-name-based IDs). Synapse and
  other homeservers sending make_join templates for room versions 10/11/12 omit
  `origin`, causing Merovingian to reject the join with "make_join event origin
  is required".
- Fix inbound make_join/make_leave template generation including the `origin` field
  in the event for room version 4+. Per the Matrix v1.18 spec, `origin` is not part
  of the event format in room versions that use reference-hash event IDs. The
  template builder now checks `EventIdFormat::reference_hash` and omits `origin`
  for room versions 4 and later.
- Fix conformance test asserting `origin` is present in make_join event templates
  for room version 12. The test was enforcing pre-v4 event format against the v1.18
  spec.

## 0.4.28

- Fix remote-join `make_join` handling to match the Matrix v1.18 join
  handshake more closely. Inbound `make_join` templates now include
  `origin` and `origin_server_ts`, and outbound remote joins now reject
  malformed `make_join` templates instead of silently repairing missing
  required fields before signing them.
- Fix restricted-room auth handling for the v1.18
  `join_authorised_via_users_server` path. Restricted joins are now accepted
  when the supplied authorising user is joined and has sufficient invite power,
  rather than being rejected unconditionally unless the target user was
  explicitly invited.
- Pin spec-facing and conformance test comments to Matrix v1.18 sections and
  add explicit guardrails telling future maintainers and LLMs to fix the
  implementation rather than weakening protocol assertions when a spec test
  fails.
- Fix federation `/send` transaction handler returning HTTP 403 for the entire
  transaction when a single PDU fails signature verification. Per the Matrix
  federation spec, individual PDU failures must be reported inside the response
  body as `{"pdus": {"$event_id": {"error": "reason"}}}` at HTTP 200. Returning
  a non-200 caused Synapse's `retryutils` to mark `pong.ping.me.uk` as a failed
  destination and back off all federation for 600 seconds, blocking join
  acknowledgements and subsequent room messages.
- Fix incremental `/sync` emitting stale room data (476 bytes of membership
  state) on every 5-second long-poll timeout re-dispatch when nothing had
  changed. The room-join loop now skips rooms where both `timeline_events` and
  `room_account_data` are empty when a `since` token is present, so the
  `rooms.join` map is empty in the response rather than repeating the full state
  of every joined room.
- Fix inbound `send_join` (v2) response missing the `"event"` field. Per Matrix
  federation spec §11.5.1 the resident server must echo the accepted join event
  back to the joining server. `MembershipAcceptResult` gains `signed_event_json`;
  `handle_send_membership` serialises it under `"event"` for `send_join` only;
  `send_leave` and `send_knock` are unaffected.

## 0.4.27

- Expand `docs/architecture.md` into a comprehensive reference covering source
  tree, runtime model, request flow, data types, database layer, federation,
  client-server API surface, sync subsystem, build system, testing, and security.
- Fix off-by-one in `/sync` `next_batch` token that caused federated users to
  get stuck in an infinite empty-sync loop after joining a room. The
  `next_batch` token was constructed from `next_stream_ordering` (a "next
  available slot" counter, always +1 ahead of the last published event) instead
  of `next_stream_ordering - 1`. This meant the client's subsequent
  `since` token pointed to a stream ordering that would never be reached, so
  the long-poll check (`stream_ordering > since_ordering`) never fired and the
  client received empty sync responses forever. Every other usage of
  `next_stream_ordering` in the codebase (the `sync_notifier->publish()` calls
  and the long-poll check itself) already applied the `- 1U` correction — only
  the token construction was missing it.

## 0.4.26

- Break the dependency between long-polling `/sync` connections and regular
  request processing. Previously the HTTP server ran all connections through a
  single 4-thread pool; a sync client waiting up to 30 s blocked one of those
  threads, leaving only 3 for everything else and making login, join, send, and
  federation feel sluggish. Fix: extract a non-blocking `route_request()` helper
  and give `serve_stream()` a `sync_pool*` parameter. When a `/sync` long-poll
  needs to wait, the main-pool thread hands the fd to the dedicated sync pool
  immediately and returns — the main pool is always free for real requests. The
  sync pool is 32 threads; the main pool grows to 8. Each async wait is capped
  at 5 s so server shutdown is bounded. TLS connections fall back to the
  existing blocking path pending TLS-session transfer support. The public
  `dispatch_local_http_request()` API retains its original blocking behaviour
  for backward compatibility with tests.
- Implement inbound `make_join` room-version negotiation. Previously the
  `membership_template_provider` ignored the remote server's `?ver=` query
  params and hardcoded `room_version = "12"`. Now it reads the actual room
  version from the `m.room.create` state event and checks whether the joining
  server advertises support for it. If not, it returns
  `M_INCOMPATIBLE_ROOM_VERSION` (HTTP 400) with the room's version in the body
  so the remote can inform its user. The `membership_acceptor` also populates
  `room_version` in the result, and `handle_send_membership` echoes it in the
  `send_join` response instead of hardcoding "12".
- Default new room version to 12 (the latest stable) across `CreateRoomOptions`,
  the `POST /_matrix/client/v3/createRoom` fallback, and the
  `GET /_matrix/client/v3/capabilities` `m.room_versions` advertisement. The
  capabilities response now also lists versions 10, 11, and 12 as `stable`
  rather than advertising only 10.
- Fix inbound PDU signature verification failure (Synapse returns 403 on every
  encrypted message): `make_event_signing_payload` now strips `event_id` from
  the signing payload when the room version uses reference-hash event IDs (all
  room versions 4+). Synapse includes `event_id` in outbound PDUs as a
  convenience hint, but its signing payload never contained the field. Our
  verification payload was therefore different from what Synapse signed, causing
  `crypto_sign_verify_detached` to fail for every inbound PDU.

## 0.4.25

- Fix remote join (make_join → send_join) failing with Synapse error "Malformed
  'hashes': `<class 'NoneType'>`": compute and attach the `hashes.sha256`
  content hash to the join event before signing it. The Matrix spec requires
  every PDU to carry this field; the remote-join code path was signing without
  hashing, producing an event Synapse (and any other spec-conformant server)
  must reject.

## 0.4.24

- Added the missing `<algorithm>` include to
  `tests/unit/test_review_regressions.cpp` so the new
  `std::ranges::find_if` regression coverage builds on FreeBSD libc++ as
  well as Linux. Linux had been passing only because another header
  happened to provide the declaration transitively.
- Make `POST /_matrix/client/v3/createRoom` conform to the Matrix v1.18
  preset and event-order rules. Room creation now derives the preset from
  `visibility`, honours requested `room_version`, merges
  `creation_content` and `power_level_content_override`, applies
  `initial_state`, emits `m.room.guest_access`, propagates `is_direct`
  into invite membership events, and implements the full
  `trusted_private_chat` extras including `additional_creators`,
  invitee power level 100, and a v12-safe `m.room.tombstone` power level.
- Register `room_alias_name` in a durable room-alias table, emit
  `m.room.canonical_alias`, expose `GET` and `PUT`
  `/_matrix/client/v3/directory/room/{roomAlias}`, and reject duplicate
  aliases with `M_ROOM_IN_USE`.
- Use the created room's actual version in outbound federation invite
  transactions instead of hardcoding version 12, so remote invitees see
  the correct auth rules for the room they are being invited to.
- Remove the listener-owned `runtime_lock` from HTTP dispatch and move
  request synchronization into `HomeserverRuntime::mutex`, so listeners no
  longer serialize every request through one process-wide lock.
- Initialize `SyncNotifier` during `start_client_server` and let
  `dispatch_local_http_request()` wait on the notifier without taking a
  separate dispatch lock.
- Release the runtime mutex before remote join discovery, `make_join`, and
  `send_join`, while snapshotting the signing key material first and
  reacquiring the mutex only for room persistence. This prevents unrelated
  client requests from blocking behind outbound federation I/O.
- Restore explicit move construction/assignment for `HomeserverRuntime` after
  adding the runtime mutex, so `start_client_server()` can still assemble the
  client runtime without breaking every CI build matrix.
- Advertise room versions 10, 11, and 12 in outbound `make_join` requests so
  federation joins succeed against rooms that use versions older than 12.
  Use the `room_version` field from the `make_join` response to select the
  correct event-auth and redaction policy when signing the join event.
- Generate the four required initial Matrix room state events (`m.room.create`,
  `m.room.member` for the creator, `m.room.power_levels`, `m.room.join_rules`)
  during `create_room` so that `send_join` returns a non-empty auth chain and
  Synapse no longer rejects remote joins with "No create event in state".
- Derive the room version policy for event composition from the room's
  `m.room.create` event instead of hardcoding version 12, so events in older
  rooms use the correct signing and auth rules.
- Remove the duplicate `m.room.create`, `m.room.member`, and `m.room.power_levels`
  `send_state` calls from the client-server `createRoom` handler; those events
  are now owned by the lower-level `create_room` function. The handler still
  sends `m.room.join_rules` (for preset override) and `m.room.history_visibility`.

## 0.4.22

- Serve `/_matrix/key/v2/server` lock-free to eliminate Synapse's
  `ServerKeyFetcher` timeout caused by concurrent `make_join` holding the
  global runtime lock. The signed response is pre-computed once during
  `start_runtime` and stored in an atomically-readable cache
  (`LocalDatabase::key_server_cache`). Subsequent key-server requests are
  served directly from the cache without waiting for the lock, keeping
  response time under Synapse's cancellation threshold even under heavy
  outbound federation load.

## 0.4.21

- Populate `old_verify_keys` in `/_matrix/key/v2/server` with any signing keys
  stored in the persistent store that are not the currently active key. Per the
  Matrix spec this allows remote servers to verify historical events signed with
  superseded keys (e.g. the legacy `ed25519:auto` key left behind after the
  key-id migration). `expired_ts` is capped at `now` so that keys stored with
  the old year-2999 sentinel are never published with a future expiry.

## 0.4.20

- Derive the server Ed25519 signing key_id from the first four bytes of the
  public key as lowercase hex (e.g. `ed25519:a1b2c3d4`) instead of the legacy
  `ed25519:auto` sentinel. This bypasses stale notary-server caches (e.g.
  matrix.org) that had `ed25519:auto` cached with a far-future `valid_until_ts`,
  which caused `BadSignatureError` on every outbound federation request.
- Ignore legacy `ed25519:auto` keys in the persistent store: treat them as
  missing and generate a fresh keypair with a derived key_id on first use.
- Set `valid_until_ts` on newly generated signing keys to `now + 7 days` (was
  year-2999 sentinel) so federation peers periodically re-fetch rather than
  caching indefinitely.
- Use the runtime signing key's actual key_id in every outbound X-Matrix header
  (`perform_sync_outbound_call`) instead of the hardcoded `"ed25519:auto"`.
- Add runtime diagnostic logging to `make_federation_signature`: logs the
  embedded public key (derived from the Ed25519 secret key bytes 32–63) and
  the signing payload size on every outbound request, making it possible to
  correlate the signing key against the published `/_matrix/key/v2/server` key
  without stopping the server.
- Log `signature.key_size_invalid` and `signature.payload_build_failed` events
  when signing is skipped due to a bad key or JSON serialisation failure.
- Log key lifecycle events (`signing_key.loaded`, `signing_key.generating`,
  `signing_key.generated`) in `ensure_runtime_server_signing_key` so operators
  can confirm whether a stable persisted key is being reused or a fresh key is
  being generated on each restart.
- Include `response_body` in the `transaction.failed` structured log field so
  error responses from remote federation peers are captured for diagnosis.

## 0.4.19

- Derive the server Ed25519 signing key_id from the first four bytes of the
  public key as lowercase hex (e.g. `ed25519:a1b2c3d4`) instead of the legacy
  `ed25519:auto` sentinel. This bypasses stale notary-server caches (e.g.
  matrix.org) that had `ed25519:auto` cached with a far-future `valid_until_ts`,
  which caused `BadSignatureError` on every outbound federation request.
- Ignore legacy `ed25519:auto` keys in the persistent store: treat them as
  missing and generate a fresh keypair with a derived key_id on first use.
- Set `valid_until_ts` on newly generated signing keys to `now + 7 days` (was
  year-2999 sentinel) so federation peers periodically re-fetch rather than
  caching indefinitely.
- Use the runtime signing key's actual key_id in every outbound X-Matrix header
  (`perform_sync_outbound_call`) instead of the hardcoded `"ed25519:auto"`.
- Add runtime diagnostic logging to `make_federation_signature`: logs the
  embedded public key (derived from the Ed25519 secret key bytes 32–63) and
  the signing payload size on every outbound request, making it possible to
  correlate the signing key against the published `/_matrix/key/v2/server` key
  without stopping the server.
- Log `signature.key_size_invalid` and `signature.payload_build_failed` events
  when signing is skipped due to a bad key or JSON serialisation failure.
- Log key lifecycle events (`signing_key.loaded`, `signing_key.generating`,
  `signing_key.generated`) in `ensure_runtime_server_signing_key` so operators
  can confirm whether a stable persisted key is being reused or a fresh key is
  being generated on each restart.
- Include `response_body` in the `transaction.failed` structured log field so
  error responses from remote federation peers are captured for diagnosis.

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
- Publish `valid_until_ts = now + 7 days` in `GET /_matrix/key/v2/server`
  instead of a far-future sentinel (year 2999). A year-2999 expiry caused
  federation peers to cache our public key permanently; when the key rotated
  between restarts (during earlier development), peers held the stale old key
  forever and rejected every `make_join` with `401 BadSignatureError`. Rolling
  the expiry ensures peers re-fetch within a week whenever the key changes.
- Add `GET /_matrix/client/v3/publicRooms` so Matrix clients can load the room
  directory after login without hitting `M_UNRECOGNIZED`; the route now lists
  locally created `public_chat` rooms from persisted room state.
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
