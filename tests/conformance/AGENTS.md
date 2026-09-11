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
| `test_admin_safety_policy_rules_conformance.cpp` | Project-specific: Merovingian admin API (trust-and-safety extension, not in the Matrix v1.19 spec) — `GET`/`PUT`/`DELETE /_matrix/client/v3/admin/safety/policy_rules` |
| `test_admin_safety_review_conformance.cpp` | Project-specific: Merovingian admin API (trust-and-safety extension, not in the Matrix v1.19 spec) — `POST /_matrix/client/v3/admin/safety/review/{targetType}/{targetId}` |
| `test_appservice_conformance.cpp` | [Application Service API](../../docs/matrix-v1.19-spec/application-service-api.md) (as_token auth, `?user_id=` masquerade, `m.login.application_service`, namespace exclusivity) |
| `test_appservice_thirdparty_conformance.cpp` | [CS API § Third-party Lookups](../../docs/matrix-v1.19-spec/client-server-api.md#third-party-lookups) |
| `test_canonicaljson_parser.cpp` | [Appendices § Canonical JSON](../../docs/matrix-v1.19-spec/appendices.md#canonical-json) |
| `test_canonicaljson_serializer.cpp` | [Appendices § Canonical JSON](../../docs/matrix-v1.19-spec/appendices.md#canonical-json) |
| `test_client_server_conformance.cpp` | [Client-Server API](../../docs/matrix-v1.19-spec/client-server-api.md) |
| `test_event_auth_rules.cpp` | [Auth Rules](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules) |
| `test_event_authorization.cpp` | [Auth Rules — Authorisation](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules) |
| `test_event_graph_conformance.cpp` | [SS API § Retrieving events](../../docs/matrix-v1.19-spec/server-server-api.md#retrieving-events) (`/state/{roomId}`, `/state_ids/{roomId}`) · [§ Backfilling and retrieving missing events](../../docs/matrix-v1.19-spec/server-server-api.md#backfilling-and-retrieving-missing-events) (`/backfill/{roomId}`) |
| `test_event_relationships_conformance.cpp` | [CS API § Event Relationships](../../docs/matrix-v1.19-spec/client-server-api.md#forming-relationships-between-events) |
| `test_events.cpp` | [SS API § Event Signing](../../docs/matrix-v1.19-spec/server-server-api.md#signing-events) · [§ Content Hash](../../docs/matrix-v1.19-spec/server-server-api.md#calculating-the-content-hash-for-an-event) |
| `test_federation_conformance.cpp` | [Server-Server API](../../docs/matrix-v1.19-spec/server-server-api.md) |
| `test_federation_media_conformance.cpp` | [SS API § Content Repository — GET /_matrix/federation/v1/media/download/{mediaId}](../../docs/matrix-v1.19-spec/server-server-api.md#content-repository) |
| `test_federation_space_media_conformance.cpp` | [SS API § Spaces](../../docs/matrix-v1.19-spec/server-server-api.md#spaces) (`/hierarchy/{roomId}`) · [§ Content Repository](../../docs/matrix-v1.19-spec/server-server-api.md#content-repository) (`/media/download/{mediaId}`) |
| `test_federation_transaction_conformance.cpp` | [SS API § PUT /send/{txnId}](../../docs/matrix-v1.19-spec/server-server-api.md#transactions) |
| `test_identifier_grammar.cpp` | [Appendices § Identifier Grammar](../../docs/matrix-v1.19-spec/appendices.md#identifier-grammar) |
| `test_ignoring_users_conformance.cpp` | [CS API § Ignoring Users](../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users) |
| `test_key_publication_conformance.cpp` | [SS API § Key publication](../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys) |
| `test_notifications_conformance.cpp` | [CS API § Push Notifications](../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications) |
| `test_outbound_delivery_conformance.cpp` | [SS API § Transactions](../../docs/matrix-v1.19-spec/server-server-api.md#transactions) · [§ EDUs](../../docs/matrix-v1.19-spec/server-server-api.md#edus) |
| `test_pdu_format_conformance.cpp` | [SS API § PDUs](../../docs/matrix-v1.19-spec/server-server-api.md#pdus) |
| `test_presence_conformance.cpp` | [CS API § Presence](../../docs/matrix-v1.19-spec/client-server-api.md#presence) |
| `test_push_notifications_conformance.cpp` | [CS API § Push Notifications](../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications) |
| `test_read_markers_conformance.cpp` | [CS API § Read and unread markers](../../docs/matrix-v1.19-spec/client-server-api.md#read-and-unread-markers) |
| `test_receipt_conformance.cpp` | [CS API § Receipts](../../docs/matrix-v1.19-spec/client-server-api.md#receipts) |
| `test_redaction_conformance.cpp` | [SS API § Redaction](../../docs/matrix-v1.19-spec/client-server-api.md#redactions) |
| `test_room_version_table_conformance.cpp` | [Room Versions](../../docs/matrix-v1.19-spec/rooms/index.md) |
| `test_safety_report_conformance.cpp` | [CS API § Reporting Content](../../docs/matrix-v1.19-spec/client-server-api.md#reporting-content) |
| `test_search_conformance.cpp` | [CS API § Server Side Search](../../docs/matrix-v1.19-spec/client-server-api.md#server-side-search) |
| `test_server_discovery.cpp` | [SS API § Resolving Server Names](../../docs/matrix-v1.19-spec/server-server-api.md#resolving-server-names) |
| `test_signing_json_conformance.cpp` | [Appendices § Signing JSON](../../docs/matrix-v1.19-spec/appendices.md#signing-json) |
| `test_sliding_sync_conformance.cpp` | [MSC4186 — Simplified Sliding Sync](https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md) (unstable; not part of v1.19) |
| `test_state_resolution_conformance.cpp` | [SS API § State Resolution](../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution) |
| `test_sync_filter_conformance.cpp` | [CS API § Filtering](../../docs/matrix-v1.19-spec/client-server-api.md#filtering) |
| `test_sync_summary_conformance.cpp` | [CS API § Syncing](../../docs/matrix-v1.19-spec/client-server-api.md#syncing) |
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
