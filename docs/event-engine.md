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
  enforcement.
- **rule 1 (`m.room.create`)**, complete since 0.12.4: no `prev_events`; the
  `room_id`/`sender` domain relationship for v1-v11 and the absence of
  `room_id` for v12 (MSC4291); a recognised `content.room_version`; and the
  creator fields (`content.creator` before v11, `content.additional_creators`
  validated as user IDs in v12). None of these was enforced before 0.12.4,
  which let a federating server mint a room whose ID claimed another
  homeserver's domain.
- **rule 8**, since 0.12.4: a state event whose `state_key` starts with `@`
  must have that key equal the `sender`. `m.room.member` never reaches this
  rule — it returns from its own branch, exactly as the spec's rule 5 does.
- **rule 9 in full**, since 0.12.4. Previously only 9.8 and 9.9 (the
  `content.users` map) were implemented. Now also: 9.1-9.3 (type validation of
  the scalar keys, of `events`/`notifications`, and of `users`), 9.5 (every
  alteration of `users_default`, `events_default`, `state_default`, `ban`,
  `redact`, `kick` or `invite` is bounded by the sender's power in both the old
  and the new direction) and 9.6/9.7 (the same two-sided bound per entry of
  `events` and `notifications`). The gap allowed a moderator to set
  `users_default` above their own level and take the room.
- **one deliberate deviation, stricter than the spec.** Rule 9.4 says a
  `m.room.power_levels` event is allowed outright when the room has no previous
  one. This server instead still requires the default `state_default` (50) in
  that case. Its `AuthEventMap` is built from local resolved state rather than
  from the event's declared `auth_events`, so "no previous power_levels" can
  also mean "this server does not have that state yet", under which a blanket
  allow would be a fail-open. The room-creation bootstrap is unaffected (the
  creator resolves to 100, or to infinite under v12). This can only reject
  where the spec would allow, never the reverse.
- **`content.events` never resolves a scalar power key.** That map keys event
  *types* to levels, so `ban`, `kick`, `redact`, `invite`, `users_default`,
  `events_default` and `state_default` are not names it can carry. Until
  0.12.4 `extract_power_level_key` fell back to it when a top-level key was
  absent, which let a sender smuggle a scalar value in under an event-type
  name and, for example, drop the effective ban level to zero. Kick/unban and ban additionally require the sender's power to
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
- auth checking wired into the federation membership endpoints — `send_join`,
  `send_leave`, and `send_knock` run the identical
  `authorize_event_against_auth_events` gate, against the room's current
  resolved state, before the membership acceptor persists the event or the
  membership row. Until 0.12.7 these endpoints verified only the inbound PDU's
  Ed25519 signature, content hash, and sender/origin consistency, then checked
  that the room existed — but signature verification establishes **who signed
  an event; it never establishes whether they are permitted to make the
  transition.** A remote server holding any valid signing key could join a
  user into an invite-only room, or move a membership it had no power level to
  move, simply by presenting a correctly signed PDU. Both write paths into the
  store — the ordinary `/send` transaction path above and the membership
  acceptor here — must enforce this gate: a rule enforced on only one of two
  paths into the same store is not enforced at all
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
- the `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}`
  endpoint (signing an intermediate invite on behalf of a remote inviter).
  `POST /invite` with a 3PID address (a real identity-server round trip,
  `homeserver::invite_user_by_threepid`, 0.12.6) and `third_party_signed`
  validation on `/join` (`verify_third_party_signed`) are implemented and
  covered by `tests/conformance/test_3pid_invite_conformance.cpp`
- room versions 1 and 2 event handling: both are registered in
  `room_version_policy.cpp`, but `EventFormat::room_v1_v2` is never consumed and
  `EventIdFormat` has only `reference_hash`, so the `$localpart:server` event-ID
  format those versions use is not implemented (see `docs/todos/capability-gaps.md`)

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

`signing_key_id_is_valid` delegates the key id's shape to
`crypto::ed25519_key_id_is_valid`, which requires the `ed25519:` algorithm
prefix. A Key ID is the algorithm and version combined (spec, Appendices
§Cryptographic key representation); a bare version string is not one.

**The signing diagnostic never carries the payload.** `sign_event_for_server`
emits each payload's byte count and SHA-256 digest, not the canonical signing
payload or the signed event JSON. Logging those put full event bodies in debug
logs, which `src/observability/AGENTS.md` forbids, and under field names the
redactor did not recognise. The digests are still enough to compare
byte-for-byte with a federation peer when triaging a `BadSignatureError`: equal
digests mean equal payloads.

Runtime signing keys are generated from system entropy using
`crypto_sign_keypair` rather than being deterministically derived from public
server identity values.

The seed is persisted encrypted under the master key and **reused across
restarts**: a new key is minted only on first boot or through an explicit
rotation, and a key whose published `valid_until_ts` window has lapsed is
republished rather than replaced. Silent regeneration is prohibited, because a
key minted behind the running signing provider can sign nothing and no peer has
ever seen it. See [ADR-0017](adr/0017-never-regenerate-a-signing-key-silently.md)
and `docs/crypto-boundary.md`.

## Event IDs

`make_content_hash` calculates the Matrix content hash over the unredacted
event after removing `unsigned`, `signatures`, and `hashes`. `make_reference_hash`
redacts the event, removes `unsigned` and `signatures`, canonicalizes, and
calculates the SHA-256 reference hash. `make_reference_hash_event_id` prefixes
the URL-safe unpadded Base64 reference hash with `$` for modern room versions.

The redaction algorithm is room-version specific, so every entry point takes the
event's own `RoomVersionPolicy` — including `make_content_hash_id`, which until
0.12.9 hardcoded version 12 regardless of the event. There is deliberately no
defaulted version: an ID computed under the wrong room version does not match
the one other servers derive.

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

Two properties of that ordering are easy to get subtly wrong and are worth
stating explicitly, because both were defects until 0.12.9:

- **Sender power is read through the room version's rules, not an integer-only
  accessor.** Room versions 1-9 permit power levels encoded as JSON strings and
  the authorization path already parses them, so an integer-only read in the
  resolver silently demoted such a sender to `users_default` and let a
  lower-power event win. `reverse_topological_power_sort` therefore takes a
  `RoomVersionPolicy` and honours `power_levels_require_integers`. **The
  resolver and `authorization.cpp` must agree on this**: if they disagree,
  events are ordered by a power level the auth rules cannot see.
- **The auth-event map built from resolved state includes
  `authorising_user_member`.** The restricted-join branch of the auth rules
  needs the `m.room.member` event of the user named by
  `content.join_authorised_via_users_server` to validate the join. Omitting it
  made every valid restricted join in the conflicted set fail auth, which
  diverges room state across federation rather than merely rejecting one event.

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
