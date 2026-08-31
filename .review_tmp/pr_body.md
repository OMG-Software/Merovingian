## Summary

Started as a documentation-only audit of the routed client-server surface against Matrix v1.19, then closed the most important gaps the audit found, then addressed ten review findings on the result. Two of the original gaps were cases where the server accepted a request and silently did nothing with it.

The audit itself is worth reading first (`docs/todos/capability-gaps.md`): the ledger implied more coverage than existed, and two whole spec sections were absent *and untracked*, so they were invisible in planning rather than merely incomplete.

## What changed

**The audit (documentation).** Added sections for the two absent APIs — **Application Service** (no `as_token`/`hs_token`, no `/_matrix/app/v1/*`, no namespace exclusivity; bridges and bots cannot run against this homeserver) and **Push Gateway**. Corrected the push rows, which claimed `spec-covered` while `POST /pushers/set` returned 200 and discarded every pusher. Added a "Reading this document" note recording the two failure modes: silence in the ledger does not imply coverage, and a routed endpoint returning 200 does not imply an implemented one.

**Push notifications — now real, gated off by default.** New `merovingian::push` module: pusher persistence, a typed rule evaluator parsed once and evaluated per event, and a Push Gateway client over the SSRF-safe `OutboundClient` with pinned addresses. Local sends, state PUTs, membership transitions **and accepted federation PDUs** all evaluate each recipient's rules and deliver off the request path, so a slow or hostile gateway can never block or fail a send. A pushkey in the gateway's `rejected` array deletes that pusher. All gated on `server.push.enabled`, default **false**.

**`GET /notifications` — routed, with bounded history.** Recorded regardless of `push.enabled` and regardless of whether a pusher is registered — only the gateway call is gated — so a user with push disabled can still read their notifications. Retention capped at 200 per user, pruned on write.

**`m.ignored_user_list` — now enforced.** A user could set the account-data key and the server ignored it entirely. Enforcement lives in one place (`trust_safety::ignore_list`) and applies at every client-facing delivery surface: `/sync`, MSC4186 sliding sync, `/messages`, `/context`, invites, push delivery, `/notifications`, and `/search`. Non-state events from an ignored sender are withheld, state events still delivered so room state stays accurate, and a new-room invite withheld. Delivery-side only — never touches persistence, auth rules, state resolution, or federation acceptance.

**`GET /rooms/{roomId}/context/{eventId}` — routed**, with `state` reconstructed at the last event returned via the same backward event-DAG walk the federation `/state` endpoints have used since 0.8.10.

**`POST /search` — routed.** In-memory search over the existing event store rather than a SQL full-text index: events are already held in memory and read linearly, so an index would mean two divergent backend implementations and a second source of truth. Bounded to avoid an unbounded scan per request.

**OpenID — both halves.** `POST /user/{userId}/openid/request_token` and the federation `GET /openid/userinfo` that redeems the token. Implementing only the client half would have minted credentials nothing could validate. The two token types are kept in separate stores with separate lookups, and rejection is proven by test in both directions.

**`AGENTS.md` — verification discipline.** A "Verifying Work" section: a run still in progress is not a result, a TIMEOUT is a failure, `testlog.txt` only captures output for failing tests, and the `pgrep -f` self-match trap. Every rule cost this branch real time.

## Why it changed

The ledger is the planning input for what gets built, so a gap it does not record is a gap nobody schedules. Two of these were active misrepresentations rather than absences: a client registering a pusher got a 200 and no notification would ever arrive, and a user asking to ignore someone got silence. For a homeserver whose stated purpose is being secure by design, accepting a safety request and discarding it is worse than not offering it.

## Defects found during the work

Each would have shipped looking like a working feature:

- **`@`-mentions would never have notified.** `event_property_is` and `event_property_contains` were unimplemented, and those back `.m.rule.is_user_mention` and `.m.rule.is_room_mention`. Caught before wiring.
- **Unbounded background tasks**, then **a shutdown deadlock** introduced by the first version of the cap — the task's final act took `orphan_futures_mutex_` while the destructor held that same mutex waiting on the task. It hung the suite for 583s and would have deadlocked server shutdown whenever a delivery was in flight.
- **`/notifications` paged with holes** — `next_token` named the first unconsumed entry but the cursor used `>=`, dropping one per page boundary — and **reported everything as read** regardless of receipts.

## Review findings addressed (10/10)

All ten from the automated review are fixed, verified, and answered inline.

| Finding | Resolution |
|---|---|
| **P1** Federation PDUs never reached push delivery | Wired at the `pdu_sink` convergence point, so both the direct and worker-relayed paths deliver without double-firing |
| **P1** Custom pusher `data` discarded | Persisted (migration 011) and forwarded; registration to `GET /pushers` to gateway proven end to end |
| **P1** Unbounded pushers per recipient | Delivery bounded to 10 per event, truncation logged |
| `delete_pusher` failure returned 200 | Result checked; a backend failure now errors instead of telling a user notifications are off while the destination stays live |
| Cross-user replacement not atomic | Replacement persisted before any removal, so a failure cannot strand other users with no pusher |
| Display name from account profile | Resolved from the recipient's `m.room.member` state for that room |
| Display name matched as a glob | Compared literally — a user named `*` was highlighted on every message |
| `.m.rule.roomnotif` deprecated | Removed, with `.m.rule.contains_display_name` on the same evidence |
| `/context` returned current state | Reconstructed at the returned position |
| `server.push.*` undocumented | Added to the manual and example config, along with `server.oidc.*` and `server.identity_server.*` |

Two were verified against the spec rather than taken on the reviewer's word, since complying wrongly would have caused a regression.

`.m.rule.roomnotif`: the `[Changed in v1.17]` note is real, and the rule appears zero times in the v1.19 spec while `is_room_mention` appears three times — so the absence is meaningful rather than an artifact of a missing section. Removed.

`/messages` was **not** changed alongside `/context`. Its `state` field has a different spec definition — "a list of state events relevant to showing the `chunk`", which is what lazy-loading needs — so applying the position-reconstruction fix there would produce differently-wrong behaviour rather than correct behaviour. That divergence is recorded in the ledger rather than left silent.

## CI tests

**49/49, 0 failures, 0 timeouts**, read from `build-wsl/meson-logs/testlog.txt` before each commit.

New test files: `test_ignoring_users_conformance.cpp`, `test_notifications_conformance.cpp`, `test_push_notifications_conformance.cpp`, `test_search_conformance.cpp`, `test_default_push_ruleset.cpp`, `test_push_delivery_flow.cpp`, `test_push_rules.cpp`, `test_push_gateway_client.cpp`, `test_push_pusher_store.cpp`, `test_trust_safety_ignore_list.cpp`, `test_runtime_orphan_futures.cpp`, `test_openid_token_store.cpp`.

Two test-shape mistakes were made and corrected here, both easy to repeat:

- Asserting event **absence** by substring search over serialized JSON is invalid. `prev_events` and `auth_events` quote earlier event IDs verbatim, so a correctly filtered response still contains a suppressed event's id inside a later event's DAG links. Those assertions are now structural, and every scenario asserts the positive counterpart so an absence check cannot pass vacuously against an empty result.
- A `rank` assertion required a JSON float, but the canonical serializer emits the shortest round-tripping form, so an integral rank arrives as an integer. JSON draws no int/float distinction; the assertion did.

## Known gaps, recorded rather than implied

The pusher bound is delivery-side only — rows still accumulate in the database, and a registration-side cap is the better guard. Email pushers are persisted but never delivered (no email transport). There is no gateway retry/backoff (spec SHOULD, not MUST). `/search` is scoped to joined rooms, not the spec's fuller "including rooms you have left". `/messages` `state` diverges from `/context` as described above.

The Application Service API remains unimplemented and is deliberately **out of scope** — it is the largest remaining surface and a security-critical one (token auth, namespace exclusivity), and will get its own PR after this merges.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
