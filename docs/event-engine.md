# Event engine

This capability note describes the Matrix event-engine foundation on top of
canonical JSON.

## Current scope

Implemented now:

- Matrix reference-hash event IDs for modern room versions using SHA-256 and
  URL-safe unpadded Base64
- Matrix content-hash calculation that removes `unsigned`, `signatures`, and
  `hashes` before canonical JSON hashing
- event envelope parsing and validation for core Matrix fields
- event signing payload construction that redacts by room version and excludes
  `unsigned` and `signatures`
- Ed25519 signature attachment, Matrix unpadded Base64 encoding, presence
  checking, and provider-backed verification against the signed payload
- runtime-created room events now receive Matrix content hashes,
  reference-hash event IDs, and Ed25519 signatures before persistence
- room-version policy registry for all stable room versions (v1-v12) used by
  version-aware auth, redaction, and state-resolution lookups
- room-version policy shape for event format, redaction rules, auth rules, state resolution, and event ID format
- redaction with room-version-dependent top-level and event-content key retention
- `origin_server_ts` uses wall-clock Unix-epoch milliseconds per Matrix spec
- event depth is persisted in the database and survives server restarts
- full Matrix v6+ event authorization rules (14-step algorithm per spec
  section 10): create events, sender-domain validation, member joins/invites/
  leaves/bans with join-rule and power-level checks, power-level elevation
  guard (applied to the sender's own entry too, per spec rule 9.9 — a user
  cannot self-elevate above their current level in a single event), removal
  and demotion guard over the union of old and new `users` keys (per spec
  rule 9.8 — a user at or above the sender's power cannot be changed or
  removed by a non-superior sender), state-default and events-default power
  enforcement. Kick/unban and ban additionally require the sender's power to
  be strictly greater than the target's own power level (spec rules 5.4/6.2)
  — the `redact`/`ban` power levels are not consulted when authorizing
  `m.room.redaction` itself (issue #410); it is authorized through the same
  `events[type]`/`events_default` path as any other message event. `redact`
  only governs whether an already-authorized redaction is *applied* to its
  target (see docs/matrix-v1.19-spec/server-server-api.md#redactions)
- auth-event map construction from current room state for authorization
- auth checking wired into the event sending path: composed events are
  authorized against current room state before persistence; auth is
  conditional on the presence of a create event in room state to allow
  the simplified room-creation bootstrap flow
- auth checking wired into the inbound federation PDU path: `pdu_sink` in
  `local_http_router.cpp` runs `authorize_event_against_auth_events` against the
  room's current resolved state before calling `store_event_with_state`; events
  that fail auth return `rejected_auth` without a non-200 HTTP status (per Matrix
  /send spec — non-200 causes the remote to back off all federation)
- room creator is implicitly treated as joined with power level 100 when
  no sender_member or power_levels event exists, enabling correct
  authorization of initial state events during room bootstrapping
- v2 state resolution algorithm: conflicted/unconflicted partition, power
  events (spec definition) sorted by reverse topological power ordering and
  auth-checked first, remaining events ordered by the mainline of the
  partially resolved power levels (transitive power-levels walk with the
  spec's ∞ sentinel for events with no mainline ancestor), iterative
  auth-based conflict resolution
- helper functions for power-level extraction, membership parsing, sender
  domain extraction
- restricted-room join auth accepts a valid
  `content.join_authorised_via_users_server` when the named resident user is
  joined and has sufficient invite power
- self-leave (`membership: "leave"`, sender matches state_key) is only
  authorized when the sender's current membership is `invite`, `join`, or
  `knock` — a banned or never-joined user cannot self-leave (which would
  otherwise flip `ban` to `leave` and let a banned user re-enter via a normal
  join/knock)
- an `m.room.member` event with an unrecognized `membership` value is
  rejected outright rather than defaulting to `leave`
- third-party (3PID) invite auth: an `m.room.member` event with `membership:
  "invite"` and a `content.third_party_invite` property is authorized against
  the full spec rule tree — target-not-banned, `signed.mxid`/`token`
  presence, `signed.mxid == state_key`, a matching `m.room.third_party_invite`
  state event for `signed.token`, sender match against that event's sender,
  and Ed25519 signature verification of the canonical `signed` payload
  (`{mxid, sender, token}`) against `content.public_key`/`public_keys` on the
  `m.room.third_party_invite` event. `m.room.third_party_invite` event
  creation itself is gated on the room's invite power level (not the generic
  `state_default` power other state events use). `crypto::ed25519_verify` is
  a new stateless verification entry point (no signing-key store needed) used
  for this and by the production `Ed25519Provider`
- unit coverage for content hashes, reference-hash event IDs, event envelope
  parsing, signing payloads, signature attachment/verification, redaction,
  room-version fixtures, full auth rule steps, and v2 state resolution

Not implemented yet:

- full Matrix room-version conformance fixture suite
- resident-side restricted-join allow-condition evaluation (requires checking
  parent-space membership when choosing whether to grant a join)
- accepting third-party invites end-to-end: `POST /invite` with a 3PID
  address/`id_server` (requires an identity-server HTTP client — otherwise the
  homeserver has no real party to source `public_key`/`public_keys` from) and
  `third_party_signed` on `/join` (requires the
  `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}` endpoint,
  or local authority to sign an intermediate invite event on behalf of the
  original inviter — a different sender than the joining user). The auth-rule
  engine above already validates either shape correctly once such an invite
  event exists in room state; only the endpoints that create/exchange it are
  outstanding

## Runtime wiring

The local runtime path now serves room creation, local joins, local sends,
state summaries, joined room listing, and bounded sync summaries through the
client-server Matrix JSON adapter. Local sends compose Matrix-shaped room
version `12` events, persist the active server signing key, store signed event
JSON, record previous-event, auth-event, and signature rows, and authorize
events against the current room state before persistence. Sync deliberately
returns event counts and membership summaries rather than plaintext event
bodies, preserving the server-blind encrypted-room posture while the full
Matrix sync stream is still unfinished.

State-event materialization follows Matrix semantics: an event is a state event
when the `state_key` member is present, including when that state key is the
valid empty string.

## Signing boundary

The event signing payload follows the Matrix event signing pipeline:

1. Redact the event with the room-version policy.
2. Remove `unsigned` and `signatures`.
3. Serialize as canonical JSON.
4. Sign the canonical bytes with the active Ed25519 provider and store the
   signature as Matrix unpadded Base64 under `signatures.<server>.<key_id>`.

Step 3 uses `canonicaljson::serialize_canonical_strict()`, not the general-purpose
`serialize_canonical()` — it fails closed with `CanonicalJsonError::float_not_allowed`
on a `Value` tree containing any double, rather than serializing one. `event_id.cpp`'s
reference-hash computation and `signable.cpp` use the same strict entry point. Floats
are already excluded from this path in practice by `parse_lossless()` rejecting them
at the parse boundary, but the strict serializer closes the same gap for any Value
tree built programmatically rather than parsed.

Verification rebuilds the same canonical payload, decodes the Matrix Base64
signature, and delegates Ed25519 verification to the configured provider.

Runtime signing keys are now generated from system entropy using
`crypto_sign_keypair` rather than being deterministically derived from public
server identity values. The secret key is held in process memory only; on
restart a new keypair is generated and the public key is upserted, effecting
automatic key rotation.

## Event IDs

`make_content_hash` calculates the Matrix content hash over the unredacted
event after removing `unsigned`, `signatures`, and `hashes`. `make_reference_hash`
redacts the event, removes `unsigned` and `signatures`, canonicalizes, and
calculates the SHA-256 reference hash. `make_reference_hash_event_id` prefixes
the URL-safe unpadded Base64 reference hash with `$` for modern room versions.

`verify_pdu_content_hash` extracts the claimed `hashes.sha256` field from an
inbound PDU and compares it against the result of `make_content_hash`. Inbound
federation PDUs are rejected before reaching the `pdu_sink` when this check
fails, as required by Matrix Server-Server API v1.19.

For room version 12 (MSC4291) the room ID is the `m.room.create` event's
reference hash with a `!` sigil — the same hash as the create event ID, which
uses `$` — and carries no `:server` domain. `create_room` composes the create
event first to derive this ID. The create event is also excluded from every other
event's `auth_events`, because the room ID already implies it. Room versions 10
and 11 keep server-scoped IDs (`!opaque:server`), a `room_id` in the create event,
and the create event in `auth_events`.

## Runtime event graph

Runtime events store their immediate `prev_events`, current-state-derived
`auth_events`, and attached server signatures in the persistent store.
Auth-event maps are built from current room state for authorization checking.
The v2 state resolution algorithm resolves conflicting state using reverse
topological power ordering for power events and the mainline ordering (based
on the partially resolved power levels) for the remaining events.

Event depth is persisted alongside the event row so ordering metadata survives
a server restart.

### State at a requested event

The inbound federation `GET /state/{roomId}` and `/state_ids/{roomId}` endpoints
return the room state resolved *as of* the required `event_id` query parameter —
the state prior to the changes that event itself induces. Because the persistent
store keeps only the current resolved state per `(type, state_key)`, historical
state is reconstructed by walking the event DAG backward from the requested
event's `prev_events`: state events are identified by the presence of a
`state_key` member in the stored PDU JSON, and for each `(type, state_key)` the
ancestor with the greatest `(depth, event_id)` wins. This is the deterministic
linearisation that v2 state resolution produces for a conflict-free DAG, so
superseded historical state values are recovered without a stored state group.
When `event_id` is absent the handler rejects the request with
`400 M_MISSING_PARAM`; an unknown `event_id` falls back to the current state.

The client-server `GET /rooms/{roomId}/context/{eventId}` endpoint reuses this
same backward DAG walk (`federation::resolve_state_event_ids_at()`, 0.11.11)
to populate its `state` field with the room state at the last event the
response actually returns, rather than the room's current state, per CS API:
"The state of the room at the last event returned." Because `/context`'s
`state` needs the pinned event's *own* contribution included when that event
is itself a state event — unlike the federation endpoints above, which stop
one step short by design — the shared walk's result is folded together with
the pinned event before being returned. `GET /rooms/{roomId}/messages` was not
changed: its `state` field is spec'd around chunk-relevance/lazy-loading, not
a DAG position, so this reconstruction does not apply to it in the same way;
see `docs/todos/capability-gaps.md` for that tracked divergence.

## Redaction

The redaction engine retains top-level keys and event-content keys according to
the supported room-version policy split (room v1–v10 vs v11+). Two room-version
policy flags refine this further:

- `create_event_is_room_id` (MSC4291, room v12): the `m.room.create` event has no
  `room_id` — the room ID is the create event's reference hash — so redaction
  drops a `room_id` from the create event. This keeps the create event's reference
  hash and signing payload byte-for-byte identical to a conformant peer's; leaving
  `room_id` in caused Synapse `send_join` to reject the create event with
  `BadSignatureError`. Every other event, and all earlier room versions, retain
  `room_id` as a protected top-level field.
- `privilege_room_creators` (MSC4289, room v12): the create event sender and the
  users listed in `content.additional_creators` hold an effectively infinite power
  level in the authorization rules, overriding any integer in `m.room.power_levels`.
  Because that privilege is implicit, creators MUST NOT also be listed in
  `m.room.power_levels` `content.users` for v12+ rooms — a conformant peer (e.g.
  Synapse) rejects a power_levels event that names a creator with
  `Creator user ... must not appear in content.users`. `create_room` therefore
  omits the creator and `additional_creators` from the emitted `users` map (and
  strips any that arrive via `power_level_content_override`) for room version 12+,
  while pre-v12 rooms keep listing the creator at level 100.

Later work must expand this with full Matrix room-version fixtures.
