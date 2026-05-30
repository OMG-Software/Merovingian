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
- room-version policy registry for modern stable room versions
- room-version policy shape for event format, redaction rules, auth rules, state resolution, and event ID format
- redaction with room-version-dependent top-level and event-content key retention
- `origin_server_ts` uses wall-clock Unix-epoch milliseconds per Matrix spec
- event depth is persisted in the database and survives server restarts
- full Matrix v6+ event authorization rules (14-step algorithm per spec
  section 10): create events, sender-domain validation, member joins/invites/
  leaves/bans with join-rule and power-level checks, power-level elevation
  guard, state-default and events-default power enforcement, redaction power
- auth-event map construction from current room state for authorization
- auth checking wired into the event sending path: composed events are
  authorized against current room state before persistence; auth is
  conditional on the presence of a create event in room state to allow
  the simplified room-creation bootstrap flow
- room creator is implicitly treated as joined with power level 100 when
  no sender_member or power_levels event exists, enabling correct
  authorization of initial state events during room bootstrapping
- v2 state resolution algorithm: conflicted/unconflicted partition, reverse
  topological power sort, mainline ordering for power-level event ties,
  iterative auth-based conflict resolution
- helper functions for power-level extraction, membership parsing, sender
  domain extraction
- restricted-room join auth accepts a valid
  `content.join_authorised_via_users_server` when the named resident user is
  joined and has sufficient invite power
- unit coverage for content hashes, reference-hash event IDs, event envelope
  parsing, signing payloads, signature attachment/verification, redaction,
  room-version fixtures, full auth rule steps, and v2 state resolution

Not implemented yet:

- signing-key rotation
- full Matrix room-version conformance fixture suite
- resident-side restricted-join allow-condition evaluation (requires checking
  parent-space membership when choosing whether to grant a join)
- third-party invite auth event handling

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
topological power ordering and mainline depth.

Event depth is persisted alongside the event row so ordering metadata survives
a server restart.

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
