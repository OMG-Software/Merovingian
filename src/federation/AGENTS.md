# src/federation/ — Federation Module

Implements the Matrix Server-Server API v1.19.
Spec authority: ../../docs/matrix-v1.19-spec/server-server-api.md

Federation is the highest-risk surface: **all input comes from untrusted remote servers.**

## Security rules — non-negotiable

1. **Authenticate every inbound request with X-Matrix auth** before touching any body data.
   Reject with `401 Unauthorized` if the header is absent, malformed, or the signature is invalid.
   See `InboundRequest.hpp` and `Security.hpp`.

2. **Verify every inbound PDU's signature** against the sending server's published key before
   allowing it to enter the event graph. Unverified events must be silently dropped (not persisted).
   There is no exception for an event whose sender is on our own server: verify it against this
   server's own signing keys (current and retired, never fetched over the network), and drop it if
   the key is not one we hold. Events in a `send_join` response must also belong to the room being
   joined; drop any other entry before verifying or storing it (ADR-0083).

   The sender's signature is not the only one. An `m.room.member` event carrying
   `join_authorised_via_users_server` must also be validly signed by that user's server
   (rooms/v10.md rule 4.2.1), and the auth rules can only see that such a signature is
   present. Every path that admits a remote PDU calls `verify_join_authorising_server_signature`
   after the sender check and refuses the event unless it accepts: `/send` and `send_join`
   through the resolver overload of `authorize_federation_pdu`, worker relay, backfill and the
   `send_join` state this server stores when it joins (`filter_verified_send_join_events`)
   directly (ADR-0171). A new ingestion path does the same.
   The rule exists from room version 8 only (rooms/v8.md rule 4.2, "New in this version"; rooms
   v3 to v7 never mention the property). The helper accepts when the policy has no
   `restricted_join_rule`, so no caller tests the version, and a prefetch of authorising keys
   skips those versions too (ADR-0356).

   Either signature is checked against every key ID the event lists for that server, not only
   the first. The sender check (`authorize_federation_pdu_sender`,
   `verify_server_signatures_on_event`) skips unknown keys and keys expired before the event's
   `origin_server_ts`, refuses the event if any other signature does not verify, and needs at
   least one that does ("If all signatures from known unexpired keys ... are found to be
   valid"; R05, ADR-0183). The authorising-server check
   (`verify_join_authorising_server_signature`) accepts any one valid signature, as its auth
   rule asks (ADR-0171). The list is written by whoever relays the event, so it is bounded:
   only `ed25519:` IDs, no repeats, each through the caller's admitted lookup; more than
   `max_signature_keys_per_server` (4) for the sender's server is refused before any lookup.
   Never pick "the" key ID with a loop that stops at the first match.

   A key a server lists under `old_verify_keys` is "only valid for signing events" (Publishing keys). The key
   response parser reads it (`RemoteKeyResponse::old_verify_keys`) and the resolver returns it as a
   `FederationKeyRecord` with `retired` set: `verify_signed_federation_request` refuses it, the X-Matrix paths never
   install it as a remote's request key, and `check_signing_key_valid_for_event` accepts it only when
   `origin_server_ts < expired_ts` (ADR-0425). `cache_remote_server_keys` stores it as a retired row
   (`server_signing_keys.expired_ts`, `valid_until_ts` equal to it): retirement is one way, the earliest expiry wins,
   a later listing under `verify_keys` never revives it, and a current key a response now lists under
   `old_verify_keys` is retired at once. A retired cached row is a cache hit (`cached_remote_key_usable`): the resolver
   never fetches for it, a worker's mirror refresh returns it as retired, `find_any_cached_remote_key` skips it, and
   nothing prunes it by `valid_until_ts`. A malformed entry is skipped alone.

   A `send_join` naming one of THIS server's users as `join_authorised_via_users_server`
   cannot carry our signature yet: the request layer and the worker relay leave that one check
   to the acceptor (`PduSignatureChecks::authorised_here`), which co-signs only after
   `homeserver::decide_restricted_join` authorises the join, and drops every signature filed
   under this server's name before signing (R04, ADR-0185). No other endpoint
   or server gets that exemption.

   The resident's answer to a `send_join` is bounded before the join is stored (F-23, ADR-0366): the acceptor plans it
   (`plan_send_join_answer`) and refuses 503 with nothing stored or sent on when it would not fit the body cap or the
   worker channel's frame. `handle_send_membership` parses the `omit_members` query parameter (only the exact value
   `true`, only on `send_join`) into `InboundPduEnvelope::omit_members` and writes `members_omitted` and
   `servers_in_room` from the acceptor's result. This server never sends `omit_members` when it joins a room
   (ADR-0241), so its own join path needs no handling of a reduced answer.

   A content-hash mismatch is never a reason to refuse an event on any path: the event is
   redacted and processed further (spec "Checks performed on receipt of a PDU", step 3). The
   membership acceptor and the invite handler redact; `handle_send_membership` and
   `handle_invite` refuse only a signature failure, with 400 `M_INVALID_PARAM` (R06).

   A failed signature is NEVER charged to the claimed origin's `RemoteTrustState`: the origin
   is unauthenticated until the signature verifies, so doing so lets any sender lock a real
   peer out (FED-4, ADR-0081). Charge it to the source address
   (`SignedFederationRequest::remote_addr`, budget `bad_signature_per_ip_rate`, 429
   `M_LIMIT_EXCEEDED`). Write `consecutive_failures` only through
   `record_remote_trust_failure()` and only after the signature has verified; the backoff
   it feeds decays after `remote_backoff_decay_window` (5 minutes).

   A failed PDU in a `/send` transaction is charged to the transport peer only when its sender
   domain is the X-Matrix origin or cannot be read: a PDU relayed from a third server verifies
   according to that server's keys, which the relay does not control, so it is dropped with its
   per-PDU error and costs the relay nothing (F-22, ADR-0346). A transaction in which any PDU
   failed verification does not reset the count. Only the transaction path writes the peer's
   trust record: a 2xx answer on any other endpoint never resets or persists it, and a worker's
   synthetic remote (ADR-0110) is never written back (F-59, ADR-0347).

3. **Fetch remote server keys via `RemoteKeyCache.hpp`** — never trust a key the remote server
   supplies inline. The key cache fetches from `/_matrix/key/v2/server` and trusts a key for at
   most 7 days after the fetch (`min(valid_until_ts, fetched_at + 7 days)`). From room v5 an event's
   signing key must be valid at the event's own `origin_server_ts`, never judged against the
   current time; v1-v4 ignore `valid_until_ts` (ADR-0075).
   A federation worker's key mirror holds only what main sent it (ADR-0733), so both its
   `cached_pdu_key_lookup` and its resolver (built with `KeyMirrorRefresh::on_miss`) ask main for the
   one server's public key rows (never `secret_key`) on a miss, before the lookup gives up or the
   resolver fetches; main never does (its mirror is authoritative).
   Never call `remote_key_resolver` directly for a network fetch: go through an admitted path so
   the fetch counts against `key_resolution_max_in_flight` and the server/key failure cache
   (FED-10). Inbound and relay verification refuse over budget (`resolve_verification_key`);
   `/send_join` state verification waits for a slot instead (`resolve_join_state_key`,
   ADR-0155), because refusing there drops member events.

4. **Run authorization rules** (`events/Authorization.hpp`) before persisting any inbound PDU.

5. **Never relay or act on a rejected or soft-failed event as if it were normal** — a rejected
   event (fails auth against its own `auth_events` or the state before it) or a soft-failed one
   (fails auth against current state) is stored and takes part in state resolution, but must never
   reach a client timeline, become a forward extremity, or drive membership/push side effects.
   Implemented in `homeserver::ingest_pdu_event` (`src/homeserver/LocalHttpRouter.cpp`, ADR-0064
   phase B2) for the `/send` transaction path, and in the membership acceptor for
   `send_join`/`send_leave`/`send_knock` (the same auth_events / state-before / current-state
   checks, redacting on a content-hash mismatch); see `docs/event-engine.md`, "Phase B2". The membership acceptor differs
   from the `/send` path in one respect (F-10, F-12, ADR-0591): it refuses a rejected or soft-failed event `403` and does not
   store it, and it first refuses a room with no local member (`room_has_current_local_interest`; `send_knock` 404, the others
   403; a `send_leave` from a remote user who holds a `join`, `invite` or `knock` row there is admitted, ADR-0747), so nothing is stored, recomputed, published or notified for either. A resent event is answered only while it is
   still the sender's accepted, current `m.room.member`.

6. **Never relay a remote server's answer about users unfiltered.** Keep only the users that
   server was asked about, and only records that describe the user they are filed under. For
   E2EE keys use `accept_remote_key_query_response()` and, for a `/keys/claim` answer,
   `accept_remote_key_claim_response()` (`KeyQuery.hpp`, ADR-0337). Merge uploaded key
   signatures only through `KeySignatures.hpp`, passing `std::nullopt` as the viewer for
   anything sent to another server (ADR-0060).
   Inbound `/user/keys/query` and `/user/keys/claim` answer for this server's users only, read keys through the
   store indexes (ADR-0603) and are refused whole, with 413, past `max_key_request_entries` (ADR-0604): never loop a
   key table per name in the request.

7. **Every room-scoped federation read checks the origin is in the room.** `/state`,
   `/state_ids`, `/event`, `/backfill` and `/get_missing_events` pass the X-Matrix-authenticated
   origin to their provider, which answers 403 `M_FORBIDDEN` unless
   `federation::origin_may_read_room()` holds (a joined user on that server in the room's
   current state, or `world_readable` history visibility). Never take the origin from the
   query string or body. The gate lives in `EventQuery.cpp`, not the handler, so it holds on
   both the worker-snapshot path and the main-relay path (`/event`, which resolves the event's
   own room). `/state` and `/state_ids` return 404 for an unknown `event_id` or one with no state this server
   recorded — never fall back to current state or to a walk of the graph (rule 19) — and `get_missing_events` is a bounded walk (limit at most 20), not
   a room scan. The server ACL check in `InboundRequest.cpp` stays in front of all of this.

   **The gate is not the whole rule: what comes back is filtered per event by server-level history
   visibility.** The S2S spec says nothing about it, so the project applies the client-server "Room
   History Visibility" settings to the requesting server (owner decision 2026-10-29). `/event`,
   `/backfill` and `/get_missing_events` send an event in full only when `ServerEventFilter` (in
   `EventQuery.cpp`; `event_visible_to_server()` for one event) finds it visible to `origin`, judged on the
   room's state AT the event (its ADR-0064 state group, never current state): `world_readable` is
   visible; `shared` (also the default when the state has no `m.room.history_visibility`) needs a user of `origin`
   joined in that state or joined now (ADR-0585); `invited`
   needs a user of `origin` invited or joined in that state; `joined` needs one joined. Any other event is
   sent REDACTED (`events::redact_event` with the room's version policy): its signatures, hashes,
   `prev_events`, `auth_events` and event ID are untouched, and it is never dropped, which would leave a hole
   in the receiver's graph. Fail closed: an event with no state group or a broken chain is redacted; if it
   cannot be redacted either (room version unknown) it is left out, never sent in full. One filter serves
   one request and builds no index of its own (the store's state-group indexes answer each lookup, ADR-0325), and a
   membership scan runs once per distinct group.
   `/state`, `/state_ids` and `/event_auth` are deliberately NOT filtered: state events are part of the
   room's authorisation, and a joining or catching-up server needs the whole of them to compute state and
   authorise events. Do not add a filter there without an ADR. A new read that returns room events goes
   through the filter.

8. **An inbound EDU's identity claims are the sending server's, so bind them to it.** A
   `m.direct_to_device` `sender` must be a user of the sending origin, and only local, active
   users may be targeted; `message_id` (1 to 32 codepoints) is de-duplicated per
   `(origin, sender, message_id)` through `EduIdempotenceWindow`, which is checked with `seen`
   and filled with `record` only after the EDU's messages have committed in one transaction
   (`database::enqueue_to_device_messages`), so a failed store never makes the resend look like
   a replay (ADR-0166). Our own outbound `message_id` is `derive_direct_to_device_message_id`
   (sender, sender device, event type, txn id), never the raw client txn id (ADR-0380). One EDU queues at most
   `max_inbound_direct_to_device_deliveries` messages, and a message whose content is over `max_to_device_message_bytes`
   is dropped alone, not the EDU (ADR-0335). A `m.device_list_update` /
   `m.signing_key_update` writes a `device_list_changes` row only for local users who share a
   joined room with the subject, as one batch (`record_device_list_changes`), one row per
   (observer, subject). It goes through `RemoteDeviceListCache` first (ADR-0560, ADR-0561): an update that
   changes nothing in the cached list writes no row, a gap (`prev_id` above the snapshot and never applied, or
   empty) or an unreadable update marks the list stale, and a subject nobody local shares a room with is erased.
   The cache is filled only from `accept_remote_user_devices_response` (whole answer or nothing) and only through
   `begin_resync` / `store_snapshot`, so an update that arrives during the fill voids it. A remote user's own membership change reaches the same table through
   `apply_membership_to_roster` (the membership acceptor and `ingest_pdu_event` both call it),
   never by editing `LocalRoom::members` directly: a join is `changed` and the leave of the last
   shared room is `left` for the local members. A published device's `unsigned.device_display_name`
   is its current name (`published_device_keys`), and `m.device_list_update` carries
   `device_display_name`. Every new EDU type needs the same three answers: whose claim is this,
   who may it reach, and what bounds its cost (audit FED-3, FED-7).

9. **An inbound `/invite` for a room whose state we hold is authorised against that state
   before we sign it, never overwrites a `ban`, and never writes room state.** The
   transaction path is what updates state. The `{eventId}` in the URL must equal the event's
   own reference-hash ID (audit FED-5).

10. **Main's `accepted_transactions` ring is the record of completed `/send` transactions.**
   The proxy routes a room's transactions to the worker or, while its reload has failed, to
   main, so a retry can reach the process that did not run the original. `FederationProxy`
   records each transaction the worker answers with 200 in main's ring and sends any
   transaction already there to main, which answers it as a duplicate. A new path that runs
   an inbound transaction outside main's handler does the same (ADR-0160). Each entry keeps the
   200 body the transaction was first answered with, and a duplicate is given that body, so a
   PDU that failed is not reported as handled on a retry. Record a completion only once its
   whole answer is built, and pass the body. The kept bodies are bounded by
   `accepted_transaction_cache_bytes` as well as the entry cap (ADR-0283).

11. **A PDU that cannot yet be placed is retained, not dropped (R03, ADR-0165).** When
   `ingest_pdu_event` cannot resolve a `prev_event`, `auth_event` or state before an
   admitted PDU, it writes the PDU to `deferred_pdus` and returns `deferred`; the `/send`
   response then has no error for it. Only a PDU that could not be retained
   (`missing_prev_state`) gets an `error` entry, because nothing will retry it. A row is
   written only by `ingest_pdu_event`, after the sender's signature was verified; the retry
   job re-enters there, so never add a path that writes `deferred_pdus` before
   verification. The set is bounded (100 per room, 1000, 16 MiB; 24 hours, 10 retries):
   keep every new write behind `upsert_deferred_pdu`.

12. **Each outbound destination holds a bounded share of the dispatch queue (ADR-0177).**
   `DispatchWorker::enqueue` refuses a transaction once its destination holds
   `effective_max_pending_per_destination` queued ones, or the queue is full, and counts it in
   `summary().rejected`. A destination's slots count its queued AND in-flight transactions:
   `push_queue_locked` takes a slot on admission (enqueue, replay), `requeue_locked` puts a
   retried transaction back without taking another, and `release_destination_slot_locked` frees
   it only when the transaction leaves for good (delivered, dropped, or failed to persist), all
   under `mutex_`. Replay parks rows past a destination's share instead of promoting them. A new
   path that touches `queue_` uses these. Destinations whose last attempt failed hold at most
   `effective_max_pending_failing` slots between them (half the queue, never below one destination's own share, ADR-0621): `remember_destination_locked` is the
   only place a destination starts or stops failing, and past the share it cuts the largest holders' newest
   transactions. A failing destination past its backoff is always admitted: never refuse it, or it can never recover.
   Destinations that deliver but slowly (an answer over a quarter of `slow_attempt_ms`) hold at most the same number
   of slots between them, refused at enqueue and never shed, and `next_ready_locked` offers their oldest row only
   when nothing else is ready (`set_slow_locked`, ADR-0720).
   A failing destination's transaction past `max_failing_transaction_age_ms` is deleted by `sweep_aged_locked`. An event's destinations go through `enqueue_batch` (ADR-0441): one durable commit, all or none on a failed commit. Never discard `enqueue`'s result: log a refusal. Give
   every destination its own transaction ID: it is the durable `federation_transactions` key.
   A failure's backoff runs from the end of the attempt (`finished_at`, `perform_outbound_transaction`'s
   `finished_clock`), never from its start: a timeout is longer than the early backoffs (ADR-0309). The
   shutdown drain takes only what was due when it began (`run_due`), so a transaction that fails during
   it waits for replay and shutdown ends. The idle wait wakes for a due transaction (`has_due_locked`),
   never for a queue that is merely not empty. `request_shutdown` sets `shutdown_requested_` while
   holding `mutex_` and notifies after releasing it: the wait predicate reads the flag under the lock,
   so a lock-free store can land between the check and the block and be lost (ADR-0312). Every
   access to the flag uses the default memory order.

13. **The private-range allowlist is for federation callers only (ADR-0231).**
   `security.federation.allow_private_ip_ranges` lets federation reach named RFC 1918 / ULA
   networks (Complement, LAN federations). `discover_server`, well-known fetches,
   `CachedServerDiscovery::discover`, `federation_discovery_policy` (the inbound origin check)
   and the remote media re-check apply it. `resolve_federation_destination` applies it only
   when the caller passes it explicitly, and `CachedServerDiscovery::lookup_addresses_filtered`
   (pushers, identity servers) never applies it. URL preview and media redirects share the
   discovery network: never pass them the allowance. Match ranges only through
   `ip_address_in_allowed_private_range`, which re-checks each range with
   `config::private_ip_range_is_allowable` so loopback and link-local can never open.

14. **An invite's `invite_room_state` is bounded in count, entry size and total bytes (`max_invite_room_state_bytes`, 64 KiB,
   ADR-0707) in every room version (ADR-0619), validated
   for room versions 12 and up, and otherwise left alone below.**
   Spec v1.19 (`PUT /v2/invite`): the list "MUST contain the `m.room.create` event" and every entry is a
   full PDU of the room version, not a stripped event. `validate_invite_room_state`
   (`InviteRoomState.cpp`) refuses with 400 `M_INVALID_PARAM` a missing create event, an entry that is
   not a version-formatted PDU, an entry in another room (a v12 create event has no `room_id`; its room is
   `!` plus its reference hash), an entry whose signature does not verify, or more than
   `max_invite_room_state_entries` (16) entries. Every entry's signature goes through the same admitted
   key lookup as the invite's own (rule 3); a lookup refused for local load is a 503, not a verdict.
   `handle_invite` calls it, and so does main's `invite_ingest` relay, because the stripped state travels in
   the relayed frame. Room versions 1 through 11 stay accepted as they arrive (spec: validation is a MAY
   there, and servers still migrating send stripped entries). Our own outbound invites and `send_knock`
   answers fill the list from `homeserver::stripped_state_pdus`.

15. **Every federation error is a standard `{errcode, error}` JSON object, and every PDU of a `/send`
   has an entry in the answer (SS API "API standards", "Transactions").** A handler may return
   `{status, "reason"}`; `handle_inbound_federation_request` wraps it with `standard_error_body`
   (errcode from the status: 400 `M_INVALID_PARAM`, 403 `M_FORBIDDEN`, 404 `M_NOT_FOUND`, ...), and
   leaves a body that already starts with `{` alone, so a handler with a more exact errcode builds
   its own `matrix_error`. The `pdus` object lists every PDU: `{}` for one that was handled (including
   one retained for retry), `{"error": ...}` otherwise. A bad `user_id` on `query/profile` is 400
   `M_INVALID_PARAM`, never a 404. `GET /event_auth/{roomId}/{eventId}` returns the closure of the
   event's `auth_events` (not the event), behind the same origin-in-room gate as the other reads
   (rule 7). A chain longer than `max_event_auth_chain_events` is refused with 502 `M_TOO_LARGE`,
   never answered with part of it (ADR-0284). The media download answers content too large to serve
   with 502 `M_TOO_LARGE`; only the thumbnail has 413. `query/directory` has no room ID, so a worker
   relays it to main (`directory_query_ingest`).

16. **A PDU whose event ID is already stored is answered as handled, before it is verified (ADR-0285).**
   Spec "PDU Processing Result": no `error` means "successfully handled". A re-send in another
   transaction, or twice in one, is looked up by event ID (any status, in the PDU's own room) first:
   `FederationRuntimeState::pdu_already_stored` in `/send` after the ACL check and before signature
   verification, `pdu_event_already_stored` on main's side of a worker `pdu_ingest` relay, and
   `ingest_pdu_event` (twice; the check under the room stripe is the decisive one). A hit is
   `PduIngestionStatus::already_stored`: empty result, not re-verified, re-authorised or stored, no
   stream ordering, push, fan-out or projection, and a stored `rejected` copy is never re-judged. The
   worker leaves `pdu_already_stored` unset (its event snapshot is not the record). A per-PDU
   `internal_error` is logged at WARNING level as well as audited: never turn a duplicate back into
   one, or the sender is told a stored event failed.

17. **Served auth chains hold the create event a room version implies (ADR-0286).** From room version 12 no event
   lists `m.room.create` in `auth_events` (rooms/v12.md: the `room_id` implies it), so the walk over
   `auth_events` never reaches it. `build_event_auth_response`, `build_state_response` (`auth_chain`) and
   `build_state_ids_response` (`auth_chain_ids`) add it through `append_implied_create_event`: once, never to the
   create event's own chain, only when this server holds it, and only for a version with
   `create_event_is_room_id`. It counts toward `max_event_auth_chain_events`. The resident's `send_join`
   `auth_chain` already holds it (its walk starts at the pre-join state). State resolution's own auth-chain
   computation and what this server accepts are not changed.

18. **A handler checks the grammar of an identifier a remote server chose before it looks it up or relays it (F-08).**
   `query/directory` (`room_alias`: `auth::room_alias_is_valid`), `user/devices` (`auth::user_id_is_valid_federated`),
   `event` (`$`, at most 255 bytes, valid UTF-8) and `make_join`/`make_leave`/`make_knock` (room ID likewise with `!`,
   user ID as above) answer 400 `M_INVALID_PARAM`, as `query/profile` does. The percent-decoder passes any byte, and a
   worker relays these to main, so a new handler that takes an identifier from the path or query does the same.

19. **Main decides the room ACL and the admin's policy for what a worker relays (F-21, F-24, ADR-0358, ADR-0359).**
   `handle_pdu_ingest_request`, `handle_membership_ingest_request` and `handle_invite_ingest_request` read
   `room_server_acl_allows` from main's store under `runtime.mutex` for the transport origin (before any key lookup) and,
   for `pdu_ingest` and `membership_ingest`, for the verified sender's server, and judge the origin's federation policy
   rule; `edu_ingest` judges the rule for the origin main authenticated and admits only an EDU whose digest the verified `/send` body carried, once per occurrence (F-74, ADR-0395; `extract_transaction_edus` and `edu_relay_digest` are the one definition of that digest). The claim and key, device-list and profile query relays are admitted only for the argument of the verified request a worker is serving, once (GHSA-3p5v-vrg8-f545, ADR-0595); `WorkerRelayBinding.hpp` (with `core::query_parameter` for the profile query's `user_id`) is the one definition of that argument and its digest, and `handle_user_devices` and every handler that reads a query parameter use the same functions, so never extract it another way. A refused PDU is `PduIngestionStatus::rejected_acl`,
   which `/send` reports as an `error` entry (a rejection is stored and silent, the opposite of the spec's "ignored with an
   error"). `load_room_server_acl` reads the ACL through `find_current_state_event_id`. A new relay does the same.
19. **The state at an event is the state this server recorded, never a walk of the event graph (F-25, F-26, ADR-0363).**
   `/state`, `/state_ids` and the client `/context` `state` answer through `state_before_event` and
   `resolve_state_event_ids_at` (`EventQuery.cpp`). The state BEFORE an event is its own state group when the event is
   not a state event or was rejected (a group holds the state AFTER its event, and a rejected event is recorded with the
   state before it), else, with a single `prev_event`, its own group with its own key's entry from that `prev_event`'s
   group (that group for any event but a fallback one, whose recorded state may hold a ban the cited fork lacks,
   ADR-0373; that group alone for an event with no group of its own), else `compute_state_before` over several
   `prev_events` under `state_read_resolution_limits` (a lowered auth-walk, ADR-0365). It fails closed with 404: no
   recorded group for the `prev_event` (outlier, the events before a federated join's own event), a broken chain, a group
   naming an event the store lacks or a rejected one. Never rebuild state from `prev_events` and `depth`: depth is the sender's, and a rejected state event
   with the largest depth would win its key. A cost that grows with the room's history is the defect; the cost is at most
   two group chains and the size of the state (`StateAtEvent::events_parsed`). The auth chain of `/state` and `/state_ids` is
   at most `max_state_auth_chain_events` (65536) and a longer one is 502 `M_TOO_LARGE`, never cut (ADR-0364). The
   functions hold no static state, take no lock and return owned data; the caller guards the store. Read current state
   with `find_current_state_event_id` and `for_each_room_state_row`, never a scan of `store.state` (ADR-0344).

20. **The operator's policy covers an event's author, and everything outbound (F-72, F-69, ADR-0390, ADR-0391).** A path that
   takes an event from another server asks `operator_policy_refusal` about the server of its `sender`, before any key is
   looked up. A worker's provider answers nothing, because main decides. An outbound path asks `federation_server_policy`, the
   config lists only, because it must not wait on `runtime.mutex`. A new path does the same.
20. **A received event is held to its room version's format by `pdu_format_violation` (F-56, F-57, ADR-0397, ADR-0399).**
   Size, `prev_events` and `auth_events` caps, and no top-level `event_id` from room version 3 on. A new path taking events from
   another server calls it. `make_event_signing_payload` is the spec's pseudocode: do not strip anything else from it.
   A resident's `make_join`/`make_leave`/`make_knock` template is such an event too: `RoomService.cpp` runs it through
   `membership_template_format_refusal` before signing it as the local user's own (F-13).
20. **A number outside Canonical JSON is that PDU's error (F-83, ADR-0398).** `parse_preserving_numbers` is for rebuilding
   what a peer signed and reading a `/send` body, never for anything this server hashes, signs or stores.
20. **A received PDU is stored without its `unsigned` (F-70, ADR-0402).** `unsigned` is outside the content hash, the
   reference hash and every signature, so the relaying server chose it, third parties' events included.
   `parse_inbound_pdu_envelope` removes it (`events::without_unsigned_json`), so `/send`, the worker relays and the
   membership acceptor store `InboundPduEnvelope::json` without it; backfill (`verify_and_store_backfilled_event`),
   the `send_join` state writer and the invite handler do the same. A new path that stores a PDU another server sent
   calls the helper, and refuses the PDU if it returns nothing. `invite_room_state` and `knock_room_state` are taken
   from the request or answer field, never from an event's `unsigned`. Removing it changes no event ID or signature check.

21. **A PDU's `depth` is required (F3, event-engine.md).** `pdu_format_violation` includes `pdu_depth_violation`: missing,
   negative, fractional, string or above 2^53 - 1 is a malformed PDU on every path that calls it (`/send`, worker relays,
   backfill, `send_join` state), never a depth of 0; `handle_invite` calls `pdu_depth_violation` itself.
22. **Third-party invites (ADR-0484, ADR-0485).** `exchange_third_party_invite` is authenticated, runs in main only
   (`federation_request_should_bypass_worker`), and its caller must be the server of `state_key`. `3pid/onbind` has no
   authentication by the spec: main answers it by exact path, reads the first `max_third_party_bind_invites` entries (the rest are counted and logged) with
   `parse_third_party_bind_notification`, and `notify_third_party_bind` bounds the work (one ADR-0079 slot, one deadline,
   no account oracle). Believe nothing in either body: the signature on `signed` is checked by the auth rules of the server that
   holds the room, and `key_validity_url` is never fetched.
23. **Discovery follows the spec's order and redirects (ADR-0483).** `.well-known` redirects are followed by
   `fetch_well_known_following_redirects` (4 hops, each re-resolved and re-checked, one shared deadline); SRV asks
   `_matrix-fed._tcp.` and then, only if empty, the deprecated `_matrix._tcp.` (`lookup_srv_with_legacy_fallback`).
21. **The published room directory has one listing and one request reader (ADR-0460, ADR-0461).** `parse_public_rooms_body` and
   `parse_public_rooms_query` refuse with 400 anything unusable; never answer a bad `since` from the first page, which loops a
   paginating server. The route names no room and reads appservice registrations, so a worker relays it to main, and main reads
   the frame with the same parser. A worker with no listing from main answers 503, never an empty directory. The page is bounded
   by the operator's page size and by `max_public_rooms_page_bytes`, and only published rooms are listed.

24. **An event builds only on events of its own room (F-01, ADR-0583).** Every path that takes a PDU asks
   `database::find_event_in_other_room` over its `prev_events` and refuses a hit: `ingest_pdu_event` (`rejected_invalid`, before
   the fetch and again after it), the membership acceptor (400 `M_INVALID_PARAM`) and backfill. `compute_state_before` refuses too.
   A foreign `prev_event` is never a gap to recover. A new path does the same.

## Key files

| File | Responsibility |
|---|---|
| `PublicRooms.cpp` | Reads a published room directory request (query or body) and writes it as the relay frame's body; the listing is `homeserver/PublicRooms.cpp` |
| `InboundRequest.cpp` | Parses and authenticates inbound federation HTTP requests |
| `InboundIngestion.cpp` | Validates, verifies, and ingests inbound PDUs |
| `OutboundTransactionSupport.cpp` | Batches local events and delivers them to remote servers |
| `ServerDiscovery.cpp` | Resolves `server_name` → host:port per SS API §Resolving Server Names |
| `RemoteKeyCache.cpp` | Caches remote server signing keys with validity TTL |
| `ThirdPartyInvite.cpp` | Parsers for `exchange_third_party_invite` and `3pid/onbind` bodies and the outbound exchange body (ADR-0484) |
| `InviteRoomState.cpp` | `validate_invite_room_state`: the `invite_room_state` checks of an inbound v12+ invite (rule 14) |
| `MembershipEndpoints.cpp` | /make_join, /send_join, /make_leave, /send_leave (a refused template carries `error_status`, e.g. 403 `M_FORBIDDEN` for a restricted room) |
| `KeyQuery.cpp` | E2EE key responses served over federation, key EDU contents (`build_device_list_update_batch` for all of a user's devices in a fixed number of table passes, F-05, never a loop of `build_device_list_update_content` over them; `build_device_list_update_content` for one, and `build_device_deleted_update_content` for a removed device: `deleted: true`, no keys), filtering remote key-query responses |
| `KeySignatures.cpp` | The one place uploaded key signatures are merged into published keys (visibility per ADR-0060); also `cross_signing_key_ids` and `device_id_names_cross_signing_key`, the device-ID versus cross-signing-key-ID test |
| `Security.cpp` | Federation-layer security checks (rate limits, origin validation, SSRF address policy) |
| `Transactions.cpp` | Transaction batching and deduplication |
| `ServerAcl.cpp`, `ServerAclGlob.cpp` | Parses and evaluates `m.room.server_acl` allow/deny lists. The glob is a two-pointer match; an ACL over 4096 patterns or with a pattern over 255 bytes, or a check over its step budget, refuses the server; parsed ACLs are cached per event, keyed with the JSON size and hash (ADR-0640). A request that checks several rooms makes one `ServerAclBudget` and passes it to every `room_server_acl_allows` (the receipt sink per EDU, a worker relay per frame); answers per (ACL event version, host) are cached (ADR-0653) |
| `RemoteDeviceListCache.cpp` | The in-memory device lists of remote users who share a room with a local user (G14, ADR-0560, ADR-0561): fill tickets, update sequencing by `stream_id`/`prev_id`, caps per user and in all. Guarded by `runtime.mutex` |
| `EduIdempotenceWindow.cpp` | Bounded in-memory replay window for `m.direct_to_device` `message_id`s, keyed on (origin, sender, message_id), plus `derive_direct_to_device_message_id` for our outbound IDs |
| `DispatchWorker.cpp` | Background outbound PDU/EDU delivery with per-destination retry and back-off; `make_dispatch_resolver` is its discovery, which never serves a remembered failure (ADR-0749) |
| `EventQuery.cpp` | Serves the room-scoped reads `event`, `state`, `state_ids`, `backfill`, `get_missing_events`, `timestamp_to_event` (seeks the store room-and-time index, steps over events `ServerEventFilter` hides, at most `max_time_search_examined` candidates; ADR-0299, ADR-0300), and owns the origin-in-room gate (`origin_may_read_room`) |
| `OutboundMembership.cpp` | Outbound `make_join` / `make_leave` / `make_knock` calls |
| `CachedServerDiscovery.cpp` | TTL-bounded in-memory cache in front of server discovery. `DiscoveryCachePolicy::successes_only` is what a call a client request triggers (the federated join's `make_join`/`send_join`) uses, so a remembered failure never refuses a retry, and so does outbound delivery, which its own backoff paces (ADR-0749); `remember_failures` stays the default for key resolution, pushers and appservices |
| `RuntimeFederationConfig.cpp` | Federation route registration and per-origin request caps |

## Adding a new federation endpoint

1. Declare handler in the relevant `.hpp`
2. Implement in the matching `.cpp`
3. Register route in `RuntimeFederationConfig.cpp`
4. Add a conformance test in `tests/conformance/` citing the spec section
5. Add an integration test in `tests/integration/test_federation_*_flow.cpp`

## Key spec sections

- [Request authentication (X-Matrix)](../../docs/matrix-v1.19-spec/server-server-api.md#request-authentication)
- [PDUs](../../docs/matrix-v1.19-spec/server-server-api.md#pdus)
- [Authorisation rules](../../docs/matrix-v1.19-spec/server-server-api.md#authorisation-rules)
- [Resolving server names](../../docs/matrix-v1.19-spec/server-server-api.md#resolving-server-names)
- [Transactions](../../docs/matrix-v1.19-spec/server-server-api.md#transactions)
- [Joining rooms](../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms)
- [Key publication](../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys)

## Outbound delivery: one thread per destination at most (F-20, ADR-0354)

`DispatchWorker` runs `delivery_threads` threads over one queue. `next_ready_locked` offers only a destination's oldest
transaction, and only with none in flight: the spec's "must wait and retry for a 200 OK" is why, so keep `requeue_locked` at
the front. Injected callbacks run concurrently. Never hold a `FederationDestination&` across a network call: an attempt works
on a copy and puts it back with `remember_destination_locked`. Do not make a slow success free: it is what let one peer hold
the only thread.

`lookup_srv` can run on several delivery threads at once, so never call a resolver function that keeps process-wide state
there. On NetBSD `res_query`, `res_search` and `res_send` all share one state with no lock, and a thread can end up blocked
reading a socket another is closing, past any budget or request to stop (ADR-0355). Do not put a lock around them instead:
one slow name server, which a remote operator chooses, would hold every other lookup.

## The federation state mutex is not recursive (ADR-0518)

`FederationRuntimeState::mutex` is a `core::CopyableMutex`, taken through `federation_guard`. Never call a function that
takes `federation_guard` while holding it: the second lock deadlocks, and a `key_resolution_slot_released` wait would
otherwise sleep with the lock held. When two operations need the same state, write a lock-held helper that expects the
caller to hold the guard (`completed_answer_with_guard_held` is the model) and call that from both.

## Wire-shape notes (analysis lows 0.12.81)

- The 64 KiB PDU limit is judged on the event without `unsigned` (`pdu_format_violation`); the raw-byte check before parsing is only a work bound (ADR-0537).
- `send_join`, `send_leave` and `send_knock` answer exactly the spec's fields (`{}` for v2 `send_leave`; no `room_version` or `origin` in `send_join`), and the v1 invite answers `[200, {"event": ...}]` (ADR-0538).
- A `/send` holding a PDU that cannot be serialised is refused 400 as a whole; the `X-Matrix` scheme is matched case-insensitively through `has_x_matrix_scheme`; a room v12 create PDU's room ID comes from `room_id_for_received_event` on every parse path.
- Outbound query values (`ver`, `v`) are percent-encoded; `max_transaction_pdus` / `max_transaction_edus` accept only 50 and 100 (ADR-0539).
