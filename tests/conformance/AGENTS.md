# Conformance Tests

This directory contains **strict Matrix v1.19 specification conformance tests** for Merovingian.

## Purpose

Every test in this directory directly encodes a **MUST** or **SHOULD** from the Matrix specification. They exist to prove that Merovingian's behaviour matches the spec exactly — not that the code compiles or that internal data structures work.

## Rules — Non-Negotiable

1. **Never weaken an assertion to make CI pass.** If a test fails, fix the implementation.
2. **Never remove or comment out a `REQUIRE`.** Removing an assertion is removing spec coverage.
3. **Never change an expected value without citing the spec change.** If a value changes, quote the spec section and version that changed it.
4. **The spec is the authority.** Not Synapse, not other implementations, not intuition.
5. **Cite the spec section above every `SCENARIO`.** Use the URL format shown below.

## File Naming Convention

| File | Spec section(s) covered |
|------|------------------------|
| `test_3pid_invite_conformance.cpp` | [CS API § Third-party invites](../../docs/matrix-v1.19-spec/client-server-api.md#third-party-invites) |
| `test_account_data_conformance.cpp` | [CS API § Client Config](../../docs/matrix-v1.19-spec/client-server-api.md#client-config) (global and room account data: JSON-object bodies, 405 for `m.fully_read`/`m.push_rules`, room ID validation, no fallback between room and global, delivery in `/sync`) |
| `test_account_lifecycle_conformance.cpp` | [CS API § User-Interactive Authentication API](../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api) (a failed stage carries `errcode`/`error`; `m.login.dummy` only within a server-issued session) · [`POST /logout`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3logout) (deletes the device; `M_MISSING_TOKEN`) · [`POST /register`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register) (username checks before UIA) · [Standard error response](../../docs/matrix-v1.19-spec/client-server-api.md#api-standards) (`M_NOT_JSON`, 405 `M_UNRECOGNIZED` on the client, media, key and federation paths) |
| `test_admin_safety_policy_rules_conformance.cpp` | Project-specific: Merovingian admin API (trust-and-safety extension, not in the Matrix v1.19 spec) — `GET`/`PUT`/`DELETE /_matrix/client/v3/admin/safety/policy_rules` |
| `test_admin_safety_review_conformance.cpp` | Project-specific: Merovingian admin API (trust-and-safety extension, not in the Matrix v1.19 spec) — `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}` |
| `test_appservice_conformance.cpp` | [Application Service API](../../docs/matrix-v1.19-spec/application-service-api.md) (as_token auth, `?user_id=` masquerade, `m.login.application_service`, namespace exclusivity) |
| `test_appservice_assertion_conformance.cpp` | [Application Service API](../../docs/matrix-v1.19-spec/application-service-api.md) (cross-service exclusive namespaces on register/login/assertion, assertion of missing or deactivated users, no identity assertion on Account Management) |
| `test_appservice_directory_conformance.cpp` | [Application Service API § Published room directories](../../docs/matrix-v1.19-spec/application-service-api.md#published-room-directories) (`PUT /directory/list/appservice/{networkId}/{roomId}`) · [CS API `POST /publicRooms`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3publicrooms) (`third_party_instance_id`, `include_all_networks`) |
| `test_appservice_ping_conformance.cpp` | [Application Service API § Pinging](../../docs/matrix-v1.19-spec/application-service-api.md#pinging) (`POST /_matrix/client/v1/appservice/{appserviceId}/ping` and the outbound `POST /_matrix/app/v1/ping`: `duration_ms`, `M_URL_NOT_SET`, `M_FORBIDDEN`, `M_BAD_STATUS`, `M_CONNECTION_FAILED`, `M_CONNECTION_TIMEOUT`) |
| `test_appservice_thirdparty_conformance.cpp` | [CS API § Third-party Lookups](../../docs/matrix-v1.19-spec/client-server-api.md#third-party-lookups) |
| `test_canonicaljson_parser.cpp` | [Appendices § Canonical JSON](../../docs/matrix-v1.19-spec/appendices.md#canonical-json) |
| `test_canonicaljson_serializer.cpp` | [Appendices § Canonical JSON](../../docs/matrix-v1.19-spec/appendices.md#canonical-json) |
| `test_client_server_conformance.cpp` | [Client-Server API](../../docs/matrix-v1.19-spec/client-server-api.md) |
| `test_content_repository_conformance.cpp` | [CS API § Content repository](../../docs/matrix-v1.19-spec/client-server-api.md#content-repository) (`{fileName}` downloads and the upload's `filename` in `Content-Disposition`, `POST /_matrix/media/v1/create`, `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}`, `timeout_ms` and `504 M_NOT_YET_UPLOADED`) |
| `test_event_auth_rules.cpp` | [Auth Rules](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules) |
| `test_event_graph_conformance.cpp` | [SS API § Retrieving events](../../docs/matrix-v1.19-spec/server-server-api.md#retrieving-events) (`/state/{roomId}`, `/state_ids/{roomId}`) · [§ Backfilling and retrieving missing events](../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events) (`/backfill/{roomId}`) |
| `test_event_relationships_conformance.cpp` | [CS API § Event Relationships](../../docs/matrix-v1.19-spec/client-server-api.md#forming-relationships-between-events) |
| `test_event_size_limits_conformance.cpp` | [CS API § Size limits](../../docs/matrix-v1.19-spec/client-server-api.md#size-limits) (locally composed events over 65536 bytes, or with a `type` or `state_key` over 255 bytes, are refused with 413 `M_TOO_LARGE` on `/send`, `/state`, membership and `createRoom`) |
| `test_event_unsigned_conformance.cpp` | [CS API § Transaction identifiers](../../docs/matrix-v1.19-spec/client-server-api.md#transaction-identifiers) · [`GET /sync`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync) (ClientEvent `unsigned.transaction_id` for the sending device only, `unsigned.membership` as the requesting user's membership at the event) |
| `test_events.cpp` | [SS API § Event Signing](../../docs/matrix-v1.19-spec/server-server-api.md#signing-events) · [§ Content Hash](../../docs/matrix-v1.19-spec/server-server-api.md#calculating-the-content-hash-for-an-event) |
| `test_federation_conformance.cpp` | [Server-Server API](../../docs/matrix-v1.19-spec/server-server-api.md) |
| `test_federation_media_conformance.cpp` | [SS API § Content Repository — GET /_matrix/federation/v1/media/download/{mediaId}](../../docs/matrix-v1.19-spec/server-server-api.md#content-repository) |
| `test_federation_membership_receipt_conformance.cpp` | [SS API § Checks performed on receipt of a PDU](../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu) · [§ Validating hashes and signatures](../../docs/matrix-v1.19-spec/server-server-api.md#validating-hashes-and-signatures-on-received-events) · [Appendices § Checking for a Signature](../../docs/matrix-v1.19-spec/appendices.md#checking-for-a-signature) (direct `send_join` / `send_leave` / `send_knock` / `invite` redact a hash mismatch and refuse a bad signature; every listed key ID is tried, within a bound; a join naming this server's user is co-signed by the acceptor) |
| `test_federation_invite_room_state_conformance.cpp` | [SS API § PUT /v2/invite](../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid) (a room version 12+ invite's `invite_room_state` must hold the create event and only signed, version-formatted PDUs of the invite's room: M_INVALID_PARAM otherwise; versions 1 to 11 accepted as sent) |
| `test_federation_space_media_conformance.cpp` | [SS API § Spaces](../../docs/matrix-v1.19-spec/server-server-api.md#spaces) (`/hierarchy/{roomId}`) · [§ Content Repository](../../docs/matrix-v1.19-spec/server-server-api.md#content-repository) (`/media/download/{mediaId}`) |
| `test_federation_transaction_conformance.cpp` | [SS API § PUT /send/{txnId}](../../docs/matrix-v1.19-spec/server-server-api.md#transactions) |
| `test_history_visibility_conformance.cpp` | [CS API § Room History Visibility](../../docs/matrix-v1.19-spec/client-server-api.md#room-history-visibility) · [`GET /rooms/{roomId}/{messages,event/{eventId},context/{eventId},members,state,initialSync}`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers) |
| `test_identifier_grammar.cpp` | [Appendices § Identifier Grammar](../../docs/matrix-v1.19-spec/appendices.md#identifier-grammar) |
| `test_ignoring_users_conformance.cpp` | [CS API § Ignoring Users](../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users) |
| `test_key_backup_conformance.cpp` | [CS API § Server-side key backups](../../docs/matrix-v1.19-spec/client-server-api.md#server-side-key-backups) (an upload for a session the backup holds keeps the better key: `is_verified`, then lower `first_message_index`, then lower `forwarded_count`) |
| `test_key_publication_conformance.cpp` | [SS API § Key publication](../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys) |
| `test_membership_projection_conformance.cpp` | [CS API § m.room.member](../../docs/matrix-v1.19-spec/client-server-api.md#mroommember) (a ban, kick or invite sent through `PUT /state/m.room.member/{userId}` takes effect as through the membership APIs; a banned user still reads pre-ban history and nothing after) |
| `test_notifications_conformance.cpp` | [CS API § Push Notifications](../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications) |
| `test_outbound_delivery_conformance.cpp` | [SS API § Transactions](../../docs/matrix-v1.19-spec/server-server-api.md#transactions) · [§ EDUs](../../docs/matrix-v1.19-spec/server-server-api.md#edus) |
| `test_pdu_format_conformance.cpp` | [SS API § PDUs](../../docs/matrix-v1.19-spec/server-server-api.md#pdus) |
| `test_pdu_ingestion_conformance.cpp` | [SS API § Checks performed on receipt of a PDU](../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu) · [Room v12 § State resolution](../../docs/matrix-v1.19-spec/rooms/v12.md) (auth_events selection: m.room.create MUST NOT be selected) |
| `test_pdu_signature_conformance.cpp` | [SS API § Validating hashes and signatures on received events](../../docs/matrix-v1.19-spec/server-server-api.md#validating-hashes-and-signatures-on-received-events) · [Room v5 § Signing key validity period](../../docs/matrix-v1.19-spec/rooms/v5.md) (key validity at `origin_server_ts`, 7-day cap) |
| `test_presence_conformance.cpp` | [CS API § Presence](../../docs/matrix-v1.19-spec/client-server-api.md#presence) (`PUT /presence/{userId}/status`) |
| `test_presence_sync_conformance.cpp` | [CS API § Presence](../../docs/matrix-v1.19-spec/client-server-api.md#presence) (`GET /presence/{userId}/status`: own presence before one is set, 403 for a user sharing no room; the `/sync` `set_presence` parameter; `m.presence` events for users sharing a room, including a user who starts sharing one) |
| `test_profile_propagation_conformance.cpp` | [CS API § Events on Change of Profile Information](../../docs/matrix-v1.19-spec/client-server-api.md#events-on-change-of-profile-information) (a display name or avatar change sends an `m.room.member` join to every room whose state holds the user joined, and answers 200 once stored even when a room cannot take it; this server's own membership events carry the profile) |
| `test_push_notifications_conformance.cpp` | [CS API § Push Notifications](../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications) |
| `test_push_rules_api_conformance.cpp` | [CS API § Push Rules: API](../../docs/matrix-v1.19-spec/client-server-api.md#push-rules-api) · [§ Push Rules: Events](../../docs/matrix-v1.19-spec/client-server-api.md#push-rules-events) (user-defined rules created, ordered by `before`/`after`, deleted, enabled and given actions; reserved IDs and server-default placements refused; the per-user rule cap; `m.push_rules` account data in `/sync` and 405 on setting it; delivery and unread counts follow the stored rules) |
| `test_read_markers_conformance.cpp` | [CS API § Read and unread markers](../../docs/matrix-v1.19-spec/client-server-api.md#read-and-unread-markers) |
| `test_receipt_conformance.cpp` | [CS API § Receipts](../../docs/matrix-v1.19-spec/client-server-api.md#receipts) (including threaded receipts, `thread_id` validation and thread-partitioned unread counts) |
| `test_redaction_conformance.cpp` | [SS API § Redaction](../../docs/matrix-v1.19-spec/client-server-api.md#redactions) |
| `test_redaction_application_conformance.cpp` | [CS API § Redactions](../../docs/matrix-v1.19-spec/client-server-api.md#redactions) (`PUT /rooms/{roomId}/redact/{eventId}/{txnId}`, `redacted_because` on every read path, `redacts` per room version) |
| `test_redaction_federation_conformance.cpp` | [Room versions § Handling redactions](../../docs/matrix-v1.19-spec/rooms/v10.md#handling-redactions) (a federated redaction is applied only when the sender has power or the original sender is on the same server) |
| `test_restricted_join_conformance.cpp` | [CS API § Restricted rooms](../../docs/matrix-v1.19-spec/client-server-api.md#restricted-rooms) (a local user joins a local restricted room through an allow condition, by a join naming a local authoriser; a user meeting no condition, or naming an authoriser through the state API, is refused; an already-joined user's copied authoriser is dropped from a profile update) |
| `test_room_admin_gates_conformance.cpp` | [CS API § Reporting content](../../docs/matrix-v1.19-spec/client-server-api.md#reporting-content), [Room upgrades](../../docs/matrix-v1.19-spec/client-server-api.md#room-upgrades), [Published room directory](../../docs/matrix-v1.19-spec/client-server-api.md#published-room-directory), [Room aliases](../../docs/matrix-v1.19-spec/client-server-api.md#room-aliases) (event reports need a joined reporter and a visible event; `/upgrade` needs tombstone power; directory visibility and alias create/delete need canonical-alias power, an administrator, or for deletion the alias creator; alias grammar and domain) |
| `test_room_api_run10_conformance.cpp` | [CS API `POST /kick`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidkick) (403 for a target not in the room), [`GET /event/{eventId}`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomideventeventid) (404 without access), [`PUT /state`](../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3roomsroomidstateeventtypestatekey) (`m.room.canonical_alias` `M_INVALID_PARAM` / `M_BAD_ALIAS`), [`createRoom`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom) (`topic` as `m.topic`, `room_version` must be a string) |
| `test_room_pagination_conformance.cpp` | [CS API `GET /rooms/{roomId}/messages`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages), [`/relations`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidrelationseventid), [`/members`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmembers), [Filtering](../../docs/matrix-v1.19-spec/client-server-api.md#filtering) (a `/sync` `next_batch` as `from` in both directions; the RoomEventFilter's `types`, `senders` and `contains_url` on `/messages`; 403, never 404, for a room the user cannot be in) |
| `test_room_summary_conformance.cpp` | [CS API § Room Summaries](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1room_summaryroomidoralias) (`GET /room_summary/{roomIdOrAlias}`: fields, `membership`, optional authentication, visibility, `allowed_room_ids`) |
| `test_room_v12_creation_conformance.cpp` | [CS API `createRoom`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3createroom), [`m.room.power_levels`](../../docs/matrix-v1.19-spec/client-server-api.md#mroompower_levels), [`POST /upgrade`](../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidupgrade), [Room v12](../../docs/matrix-v1.19-spec/rooms/v12.md) (the initial tombstone level; `M_INVALID_ROOM_STATE` for a creator in the power-level override or an invalid `additional_creators`; `room_id` on the v12 create event for clients; upgrades apply `additional_creators`, copy `type` and transfer state without the new creators) |
| `test_room_version_table_conformance.cpp` | [Room Versions](../../docs/matrix-v1.19-spec/rooms/index.md) |
| `test_safety_report_conformance.cpp` | [CS API § Reporting Content](../../docs/matrix-v1.19-spec/client-server-api.md#reporting-content) |
| `test_search_conformance.cpp` | [CS API § Server Side Search](../../docs/matrix-v1.19-spec/client-server-api.md#server-side-search) |
| `test_server_discovery.cpp` | [SS API § Resolving Server Names](../../docs/matrix-v1.19-spec/server-server-api.md#resolving-server-names) |
| `test_signing_json_conformance.cpp` | [Appendices § Signing JSON](../../docs/matrix-v1.19-spec/appendices.md#signing-json) |
| `test_sliding_sync_conformance.cpp` | [MSC4186 — Simplified Sliding Sync](https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md) (unstable; not part of v1.19) |
| `test_state_resolution_conformance.cpp` | [SS API § State Resolution](../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution) |
| `test_sync_archive_conformance.cpp` | [CS API `GET /sync`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync) (`rooms.leave`: the filtered timeline up to the leave or ban, state as of the leave, a leave reported once) |
| `test_sync_filter_conformance.cpp` | [CS API § Filtering](../../docs/matrix-v1.19-spec/client-server-api.md#filtering) |
| `test_sync_summary_conformance.cpp` | [CS API § Syncing](../../docs/matrix-v1.19-spec/client-server-api.md#syncing) |
| `test_sync_state_conformance.cpp` | [CS API `GET /sync`](../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync) (a joined room's `state` is the state up to the start of the timeline, not current state) |
| `test_typing_conformance.cpp` | [CS API § Typing Notifications](../../docs/matrix-v1.19-spec/client-server-api.md#typing-notifications) (`typing` must be a boolean; typing expires after its `timeout`, never later than the server's ceiling) |
| `test_x_matrix_auth_parsing.cpp` | [SS API § X-Matrix Auth](../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication) |

## How to Write Conformance Tests

Every `SCENARIO` must carry a spec citation in the comment block immediately above it:

```cpp
// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: <name>
// URL: ../../docs/matrix-v1.19-spec/index.md>/#<anchor>
//
// Summary of the MUST/SHOULD being tested.
SCENARIO("descriptive test name", "[area][conformance][tag]")
```

- Use `[conformance]` as a tag on every scenario.
- Add additional tags matching the spec area: `[canonicaljson]`, `[federation]`, `[client-server]`, `[auth]`, `[signing]`, `[identifiers]`, etc.
- Each `REQUIRE` line should have a one-line comment quoting "Spec MUST:" or "Spec SHOULD:" with the key constraint.

## When a Test Fails

A failing conformance test means **the implementation is wrong**, not the test. The correct response is always:

```
Fix the implementation → verify the fix → re-run → confirm the test passes
```

Do **not** amend the test to accept the wrong behaviour.

## Spec Reference

- Base spec: ../../docs/matrix-v1.19-spec/index.md
- Client-Server API: ../../docs/matrix-v1.19-spec/client-server-api.md
- Server-Server API: ../../docs/matrix-v1.19-spec/server-server-api.md
- Room Versions: ../../docs/matrix-v1.19-spec/rooms/index.md
- Appendices: ../../docs/matrix-v1.19-spec/appendices.md
