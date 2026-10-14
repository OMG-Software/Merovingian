# Reject NUL before mutation and path decoding

* Status: proposed
* Date: 2026-10-12

Technical Story: DB-6 in the 2026-09-29 security audit; reviewed admission checkpoint passed a fresh combined suite, with extended decoder-consumer verification still outstanding.

## Context and Problem Statement

A state key can reach local stream-order allocation and room/bootstrap persistence before a database binding rejects NUL. Inbound parsing alone does not protect local composition, and checking initial-state entries as they are composed allows earlier entries to leave partial durable progress.

The shared path-component decoder rejects literal or once-decoded NUL. Calling it without admission checks at dispatch boundaries can lose a structured HTTP refusal, including on a real keep-alive federation connection. Some recognized join-server query hints also use that decoder, while unrelated query data and JSON or binary payloads are different domains.

## Decision Drivers

* Refuse unsupported text state keys before business mutations or watermark allocation.
* Preserve one percent-decoding pass and valid empty, Unicode, JSON-content and binary data.
* Return controlled errors without reflecting untrusted targets or misclassifying unrelated exceptions.
* Preserve existing rows, event identities, signatures and historical derivations without implicit rewriting.

## Considered Options

* Validate at the owning admission boundaries with shared, narrow predicates.
* Rely on SQL text binding or validate each initial-state entry during composition.
* Blanket-reject NUL throughout requests, double-decode escapes, or relabel all `invalid_argument` exceptions.
* Replace text storage or normalize existing state keys as part of this repair.

## Decision Outcome

Chosen option: "Validate at the owning admission boundaries with shared, narrow predicates", because the rejection must precede both storage and in-memory mutations, and each input domain needs its own compatibility boundary.

Reuse `events::state_key_contains_nul` for inbound parsing and local composition. Preflight the **complete** create-room initial-state list before room/bootstrap persistence, and reject a direct local state send before stream-order allocation with `400 M_INVALID_PARAM`.

Use `core::path_component_contains_nul` on the path before the first query separator, ahead of any path decoder or routing helper. Literal NUL and `%00` are refused; `%2500` is decoded once into literal `%00`, not decoded again into NUL. The public client refusal retains configured CORS. The federation dispatcher emits a structured Matrix error before normal or verified-worker replay. A proxy routes before that dispatcher, so `FederationProxy::handle` has its own check before bypass/authentication/shard-key decoding. Real healthy-proxy/separate-worker verification is separate from dispatcher success.

Check recognized `via`/`server_name` join hints separately at every consumer before their path-style decoding, including direct-local room joins. Strip the query before extracting send/redact/state/report/typing path components, to-device transaction IDs, knock room IDs, shared user-metadata suffixes, device IDs and backup-version DELETE IDs; path admission alone cannot protect consumers accidentally given query text. Leave unrelated query values, escaped NUL in JSON content and binary media outside the path/state-key guards. Do not broadly catch unrelated `invalid_argument` exceptions or reflect request targets in refusals.

This is an implementation storage-compatibility constraint, not a claim that Matrix universally forbids NUL in strings. No existing data is normalized, migrated or rehashed by this decision. Future support for NUL text state keys would require an explicit storage representation and compatibility decision, not a silent truncation or key rewrite.

### Positive Consequences

* Refused local input cannot allocate watermarks or leave partial room/bootstrap writes.
* Narrow checks preserve literal-percent path compatibility and independent JSON/binary handling.
* HTTP refusal and keep-alive behavior can be tested through real authenticated transports.

### Negative Consequences

* Unsupported text state keys are explicitly rejected rather than made representable in PostgreSQL text.
* All dispatch consumers must be traced: a proxy or query-hint decoder can run before an otherwise protected handler.
* Existing malformed rows are not repaired by an admission-only change.

## Pros and Cons of the Options

### Rely on SQL binding or per-entry composition checks

* Good, because it centralizes the database's text constraint.
* Bad, because it is too late to protect earlier in-memory, watermark or bootstrap mutations.

### Blanket filtering, repeated decoding or generic exception conversion

* Good, because the check appears easy to apply globally.
* Bad, because it changes valid payloads, conflates input domains and hides unrelated failures.

### Storage replacement or key normalization

* Good, because a designed representation could support additional text values.
* Bad, because it requires explicit schema/compatibility work; normalization can collide identities or invalidate signed event data.

## Verification and Acceptance Boundary

Local, client, recognized join-query and isolated real PostgreSQL regressions have executed with mutation/compatibility checks. The separate no-proxy socket scenario first failed behaviorally, then passed with complete `400` replies, authenticated same-socket controls, one-pass percent compatibility and unchanged memory/reopened SQLite business rows and watermarks.

The separate real healthy-proxy/worker scenario also failed behaviorally before the main proxy guard, then passed with worker-served controls and no failed-room-sync fallback. An isolated real PostgreSQL admission/compatibility rerun after that repair passes with verified service teardown and unchanged source state.

Independent federation-slice source review passed. A broader review exposed client query/path mixing, unguarded direct-local join hints and PostgreSQL test configuration incompatible with the existing URI-only gate. Subsequent genuine query/path and local-hint REDs are repaired and pass 230 / 1 and 188 / 1. The PostgreSQL tests now own a private connection file from exactly the explicitly selected test URI; URI-only and URI-plus-file isolated runs each pass 178 / 2 with verified teardown. Production credential readers and CI opt-in gates are unchanged.

The bounded repair review passed with no security or logic findings; all seven reviewed files matched executed GREEN. The fresh review-gap full CLI completed exit 0: 56 OK, no failures/timeouts, fresh archived text/JSON reports, all return codes zero and 127 unchanged snapshotted files. This accepts that checkpoint, not later edits. Further tracing found raw query text reaching to-device, knock and user-metadata paths. Their separate real SQLite regression failed 34 / 169 checks, then passed 255 / 1 after path-only extraction; a declaration-order compilation attempt is recorded as a build failure, not behavioral RED. Current normal DB-6 integration passes 1595 / 12; isolated PostgreSQL URI-only and URI-plus-file reruns after this repair each pass 178 / 2 with verified owned-file cleanup, cluster shutdown/removal and stable source snapshots. The extended review found no blocking defect in those three repairs or their test, but rejected decoder completeness. Parent inspection corroborates raw target slicing in public profile GET, profile PUT, shared room action/receipt suffixes and presence, including ordinary-query receipt event-ID mutation. A separately registered real SQLite/password-authenticated regression then reproduced 206 failed / 691 assertions after its mandatory complete no-query control passed; all eight nonempty query/marker cases failed. Only then were profile GET/PUT, shared room suffixes and presence changed to use the existing path-only request view. GREEN passes 733 / 1, current normal DB-6 integration passes 2328 / 13, and unchanged unit groups pass. Current isolated PostgreSQL URI-only and URI-plus-file reruns each pass 178 / 2 with verified cleanup/teardown; all 22 current admission sources match the executed integration/unit/both-database snapshots and scoped static findings are unchanged.

The subsequent source review rejected an introduced `/members` query-loss regression: query parsing still used the now-clean suffix. Its real-dispatch conformance failed 50 / 164 assertions, then passed 164 / 1 after query extraction from the original request was separated from path-only identity extraction. A separate pre-existing combined-filter intersection failed 16 / 73, then passed 73 / 1 after implementing the specification's union semantics. Current history conformance passes 1816 / 17; normal DB-6 integration remains 2328 / 13, units remain green, and both current isolated PostgreSQL modes pass 178 / 2 with verified teardown. All 23 current admission sources match the executed conformance/integration/unit/both-database manifests and scoped static findings are unchanged. Fresh member-repair source review passed with no security or logic findings; both reviewed files match executed GREEN. The subsequent postmembers full checkpoint passed 56 OK targets, all return codes zero and no failures/timeouts, with 129 unchanged snapshotted files. This accepts that earlier snapshot only. The SQLite scenario checks durable profile/presence/fully-read/leave identities and exact in-memory receipt event IDs, not every room action or presence GET.

The independently identified nondecoder device and backup-version query identity defects now have separate behavioral RED/GREEN evidence. After a real public device login and successful no-query control, device GET/PUT/password-UIA DELETE failed 56 / 216 assertions; path-only device extraction passes 224 / 1 with durable target deletion, session revocation and preservation of the owner's device/session. Backup-version DELETE failed 24 / 181 after a healthy control, including HTTP success leaving the intended version undeleted; path-only version extraction passes 181 / 1 with reopened durable rows, another version preserved and repeat deletion. Current normal DB-6 integration passes 2733 / 15, history conformance remains 1816 / 17 and unit groups remain green. Both isolated PostgreSQL admission/compatibility modes pass 178 / 2 with verified teardown and owned fixture removal; all five execution manifests match the same 23 current sources. This does not establish live-PostgreSQL device/backup operations, arbitrary encoded device IDs, backup encryption/session cascade or new wire coverage. Bounded independent review of this addition passed with no security or logic findings; parent inspection bound all four statements and both scenarios to executed GREEN. Fresh combined acceptance passed 56 OK targets, all return codes zero and no failures/timeouts, against 130 unchanged snapshotted files including the focused sources. The source freeze ended after that acceptance. Exact UIA challenge structure and stronger reopened owner-token/survivor-metadata comparisons remain nonblocking coverage suggestions. The record remains proposed. Focused success is not whole DB-6 closure. Raw-wire NUL, TLS, hardened-worker startup and every federation route are not claimed as socket coverage.

## Links

* [HTTP transport: structured errors](../http-transport.md#structured-errors)
* [Event engine](../event-engine.md)
* [Require explicit selection of the test-only memory database](0093-require-explicit-test-memory-database.md)
