# src/federation/ — Federation Module

Implements the Matrix Server-Server API v1.19.
Spec authority: ../../docs/matrix-v1.19-spec/server-server-api.md

Federation is the highest-risk surface: **all input comes from untrusted remote servers.**

## Security rules — non-negotiable

1. **Authenticate every inbound request with X-Matrix auth** before touching any body data.
   Reject with `401 Unauthorized` if the header is absent, malformed, or the signature is invalid.
   See `inbound_request.hpp` and `security.hpp`.

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

   A `send_join` naming one of THIS server's users as `join_authorised_via_users_server`
   cannot carry our signature yet: the request layer and the worker relay leave that one check
   to the acceptor (`PduSignatureChecks::authorised_here`), which co-signs only after
   `homeserver::decide_restricted_join` authorises the join, and drops every signature filed
   under this server's name before signing (R04, ADR-0185). No other endpoint
   or server gets that exemption.

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

3. **Fetch remote server keys via `remote_key_cache.hpp`** — never trust a key the remote server
   supplies inline. The key cache fetches from `/_matrix/key/v2/server` and trusts a key for at
   most 7 days after the fetch (`min(valid_until_ts, fetched_at + 7 days)`). From room v5 an event's
   signing key must be valid at the event's own `origin_server_ts`, never judged against the
   current time; v1-v4 ignore `valid_until_ts` (ADR-0075).
   A federation worker's key mirror is a snapshot taken at start-up, so its resolver is built with
   `KeyMirrorRefresh::on_miss` and re-reads the one server's public key rows (never `secret_key`) from
   the database before it fetches; main's resolver never does (its mirror is authoritative).
   Never call `remote_key_resolver` directly for a network fetch: go through an admitted path so
   the fetch counts against `key_resolution_max_in_flight` and the server/key failure cache
   (FED-10). Inbound and relay verification refuse over budget (`resolve_verification_key`);
   `/send_join` state verification waits for a slot instead (`resolve_join_state_key`,
   ADR-0155), because refusing there drops member events.

4. **Run authorization rules** (`events/authorization.hpp`) before persisting any inbound PDU.

5. **Never relay or act on a rejected or soft-failed event as if it were normal** — a rejected
   event (fails auth against its own `auth_events` or the state before it) or a soft-failed one
   (fails auth against current state) is stored and takes part in state resolution, but must never
   reach a client timeline, become a forward extremity, or drive membership/push side effects.
   Implemented in `homeserver::ingest_pdu_event` (`src/homeserver/local_http_router.cpp`, ADR-0064
   phase B2) for the `/send` transaction path, and in the membership acceptor for
   `send_join`/`send_leave`/`send_knock` (the same auth_events / state-before / current-state
   checks, redacting on a content-hash mismatch); see `docs/event-engine.md`, "Phase B2".

6. **Never relay a remote server's answer about users unfiltered.** Keep only the users that
   server was asked about, and only records that describe the user they are filed under. For
   E2EE keys use `accept_remote_key_query_response()` (`key_query.hpp`). Merge uploaded key
   signatures only through `key_signatures.hpp`, passing `std::nullopt` as the viewer for
   anything sent to another server (ADR-0060).

7. **Every room-scoped federation read checks the origin is in the room.** `/state`,
   `/state_ids`, `/event`, `/backfill` and `/get_missing_events` pass the X-Matrix-authenticated
   origin to their provider, which answers 403 `M_FORBIDDEN` unless
   `federation::origin_may_read_room()` holds (a joined user on that server in the room's
   current state, or `world_readable` history visibility). Never take the origin from the
   query string or body. The gate lives in `event_query.cpp`, not the handler, so it holds on
   both the worker-snapshot path and the main-relay path (`/event`, which resolves the event's
   own room). `/state` and `/state_ids` return 404 for an unknown `event_id` — never fall
   back to current state — and `get_missing_events` is a bounded walk (limit at most 20), not
   a room scan. The server ACL check in `inbound_request.cpp` stays in front of all of this.

   **The gate is not the whole rule: what comes back is filtered per event by server-level history
   visibility.** The S2S spec says nothing about it, so the project applies the client-server "Room
   History Visibility" settings to the requesting server (owner decision 2026-10-29). `/event`,
   `/backfill` and `/get_missing_events` send an event in full only when `ServerEventFilter` (in
   `event_query.cpp`; `event_visible_to_server()` for one event) finds it visible to `origin`, judged on the
   room's state AT the event (its ADR-0064 state group, never current state): `world_readable` or
   `shared` (also the default when the state has no `m.room.history_visibility`) is visible; `invited`
   needs a user of `origin` invited or joined in that state; `joined` needs one joined. Any other event is
   sent REDACTED (`events::redact_event` with the room's version policy): its signatures, hashes,
   `prev_events`, `auth_events` and event ID are untouched, and it is never dropped, which would leave a hole
   in the receiver's graph. Fail closed: an event with no state group or a broken chain is redacted; if it
   cannot be redacted either (room version unknown) it is left out, never sent in full. One filter serves
   one request, so the group index is built once and a membership scan runs once per distinct group.
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
   (sender, event type, txn id), never the raw client txn id. One EDU queues at most
   `max_inbound_direct_to_device_deliveries` messages. A `m.device_list_update` /
   `m.signing_key_update` writes a `device_list_changes` row only for local users who share a
   joined room with the subject, as one batch (`record_device_list_changes`), one row per
   (observer, subject). A remote user's own membership change reaches the same table through
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
   path that touches `queue_` uses these. Never discard `enqueue`'s result: log a refusal. Give
   every destination its own transaction ID: it is the durable `federation_transactions` key.

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

14. **An invite's `invite_room_state` is validated for room versions 12 and up, and left alone below.**
   Spec v1.19 (`PUT /v2/invite`): the list "MUST contain the `m.room.create` event" and every entry is a
   full PDU of the room version, not a stripped event. `validate_invite_room_state`
   (`invite_room_state.cpp`) refuses with 400 `M_INVALID_PARAM` a missing create event, an entry that is
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

## Key files

| File | Responsibility |
|---|---|
| `inbound_request.cpp` | Parses and authenticates inbound federation HTTP requests |
| `inbound_ingestion.cpp` | Validates, verifies, and ingests inbound PDUs |
| `outbound_transaction.cpp` | Batches local events and delivers them to remote servers |
| `server_discovery.cpp` | Resolves `server_name` → host:port per SS API §Resolving Server Names |
| `remote_key_cache.cpp` | Caches remote server signing keys with validity TTL |
| `invite_room_state.cpp` | `validate_invite_room_state`: the `invite_room_state` checks of an inbound v12+ invite (rule 14) |
| `membership_endpoints.cpp` | /make_join, /send_join, /make_leave, /send_leave (a refused template carries `error_status`, e.g. 403 `M_FORBIDDEN` for a restricted room) |
| `key_query.cpp` | E2EE key responses served over federation, key EDU contents, filtering remote key-query responses |
| `key_signatures.cpp` | The one place uploaded key signatures are merged into published keys (visibility per ADR-0060) |
| `security.cpp` | Federation-layer security checks (rate limits, origin validation, SSRF address policy) |
| `transactions.cpp` | Transaction batching and deduplication |
| `server_acl.cpp` | Parses and evaluates `m.room.server_acl` allow/deny lists |
| `edu_idempotence.cpp` | Bounded in-memory replay window for `m.direct_to_device` `message_id`s, keyed on (origin, sender, message_id), plus `derive_direct_to_device_message_id` for our outbound IDs |
| `dispatch_worker.cpp` | Background outbound PDU/EDU delivery with per-destination retry and back-off |
| `event_query.cpp` | Serves the room-scoped reads `event`, `state`, `state_ids`, `backfill`, `get_missing_events`, `timestamp_to_event` (seeks the store room-and-time index, steps over events `ServerEventFilter` hides, at most `max_time_search_examined` candidates; ADR-0299, ADR-0300), and owns the origin-in-room gate (`origin_may_read_room`) |
| `outbound_membership.cpp` | Outbound `make_join` / `make_leave` / `make_knock` calls |
| `cached_server_discovery.cpp` | TTL-bounded in-memory cache in front of server discovery. `DiscoveryCachePolicy::successes_only` is what a call a client request triggers (the federated join's `make_join`/`send_join`) uses, so a remembered failure never refuses a retry; `remember_failures` stays the default for key resolution, pushers and appservices |
| `runtime_federation.cpp` | Federation route registration and per-origin request caps |

## Adding a new federation endpoint

1. Declare handler in the relevant `.hpp`
2. Implement in the matching `.cpp`
3. Register route in `runtime_federation.cpp`
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
