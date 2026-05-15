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
- unit coverage for content hashes, reference-hash event IDs, event envelope
  parsing, signing payloads, signature attachment/verification, redaction, and
  room-version fixtures

Not implemented yet:

- signing-key rotation
- event authorization rules
- auth event selection
- full state resolution
- full Matrix room membership behavior
- full Matrix room-version conformance fixture suite

## Runtime wiring

The local runtime path now serves room creation, local joins, local sends,
state summaries, joined room listing, and bounded sync summaries through the
client-server Matrix JSON adapter. Local sends compose Matrix-shaped room
version `12` events, persist the active server signing key, store signed event
JSON, and record previous-event, auth-event, and signature rows. Sync
deliberately returns event counts and membership summaries rather than plaintext
event bodies, preserving the server-blind encrypted-room posture while the full
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
`auth_events`, and attached server signatures in the persistent store. This is
the first durable DAG slice; full auth-event selection and state resolution
remain separate work.

Event depth is persisted alongside the event row so ordering metadata survives
a server restart.

## Redaction

The redaction engine retains top-level keys and event-content keys according to
the supported room-version policy split. Later work must expand this with full
Matrix room-version fixtures.
