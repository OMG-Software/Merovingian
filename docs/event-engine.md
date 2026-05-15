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
- unit coverage for content hashes, reference-hash event IDs, event envelope
  parsing, signing payloads, signature attachment/verification, redaction,
  room-version fixtures, full auth rule steps, and v2 state resolution

Not implemented yet:

- signing-key rotation
- full Matrix room-version conformance fixture suite
- restricted join rule evaluation (requires parent-space membership)
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
the supported room-version policy split. Later work must expand this with full
Matrix room-version fixtures.
