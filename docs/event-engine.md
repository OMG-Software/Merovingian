# Event engine

This capability note describes the Matrix event-engine foundation on top of
canonical JSON.

## Current scope

Implemented now:

- Matrix reference-hash event IDs for modern room versions using SHA-256 and
  URL-safe unpadded Base64
- Matrix content-hash calculation that removes `unsigned`, `signatures`, and
  `hashes` before canonical JSON hashing
- federated join and leave templates replace any existing `hashes` object
  with the freshly calculated `sha256` content hash before signing, so a
  resident server's template cannot cause duplicate JSON members in the
  outgoing event (Matrix v1.19
  [adding hashes and signatures](matrix-v1.19-spec/server-server-api.md#adding-hashes-and-signatures-to-outgoing-events))
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
- redaction with room-version-dependent top-level and event-content key retention.
  Beyond the `RedactionRules` buckets (v1–v7, v8–v10, v11+), two
  `RoomVersionPolicy` flags carry finer rules: `redaction_keeps_aliases`
  (m.room.aliases keeps `aliases` in v1–v5 only; rooms/v6.md removed it) and
  `redaction_keeps_join_authorisation` (m.room.member keeps
  `join_authorised_via_users_server` from v9). No version keeps any
  m.room.third_party_invite content (0.12.13; the redacted form feeds the
  reference hash, so a divergence here changes event IDs)
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
- auth checking wired into the inbound federation PDU path: `pdu_sink`
  (`ingest_pdu_event`, `local_http_router.cpp`) originally ran
  `authorize_event_against_auth_events` against the room's current resolved
  state only, before calling `store_event_with_state`; events that fail auth
  return `rejected_auth` without a non-200 HTTP status (per Matrix /send spec
  — non-200 causes the remote to back off all federation). **Superseded by
  ADR-0064 phase B2** (above): the current-state check is now the *soft-fail*
  step (step 6), run only after separate auth checks against the event's own
  `auth_events` (step 4, reject) and the state before the event (step 5,
  reject) — see "Phase B2: the receipt-order auth checks themselves" above.
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
- each join rule is recognised only in the room versions that define it
  (`RoomVersionPolicy::knock_join_rule` v7+, `restricted_join_rule` v8+,
  `knock_restricted_join_rule` v10+). From v10, `knock_restricted` joins
  follow the restricted rule (rules 4.3.5) and knocks accept `knock` or
  `knock_restricted`; before v7 a `knock` membership is rejected. A join rule
  the version does not define, including the non-spec `restricted_v2`, falls
  through to "Otherwise, reject" (0.12.13)
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
- **inbound federation PDU size and field-count limits enforced before
  hashing/authorization (0.12.13, M3).** Raw PDU JSON is capped at 65 536
  bytes, `prev_events` at 20, and `auth_events` at 10, all checked in
  `parse_inbound_pdu_envelope` before any content hashing or signature work.
  `sender`, `room_id`, `state_key`, and `type` are capped at 255 bytes by
  `matrix_id_is_valid` and `parse_event_envelope`. See
  `include/merovingian/events/limits.hpp` and
  [ADR-0067](adr/0067-enforce-federation-pdu-size-and-field-limits-before-hashing.md).
- **`content.m.federate: false` enforced for every room version (0.12.13,
  M4).** Authorization rule step 3 now rejects cross-domain senders in v1–v5
  rooms that disable federation, not only in v6+ and v12. When `m.federate`
  is absent or `true`, cross-domain senders remain permitted in all versions.
  Test: `tests/conformance/test_event_auth_rules.cpp` (`[m04]`).

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
on the partially resolved power levels) for the remaining events. Room v12
uses state-res v2.1: the same algorithm with three modifications (below).

### Auth difference, full conflicted set, and the v12 conflicted state subgraph

Until 0.12.13, `resolve_state_v2` only ever considered power events that
appeared literally as one of the two conflicted state groups' entries. The
spec's Algorithm step 1 is broader: *"Select the set X of all power events
that appear in the **full conflicted set**"*, where the full conflicted set is
the conflicted state set **plus the auth difference** — events reachable only
through the `auth_events` chains of the conflicted events, not present as a
literal value in either fork's state. A power-level change hidden this way
(e.g. authorising a later ban) was silently invisible to the old resolver,
letting the ban it authorised be dropped even though the promoting event was
never actually in dispute — two conformant servers could resolve the same
input differently. `StateResolutionRequest::event_lookup` gives the resolver a
way to fetch those ancestor events (the persistent store, in production; see
`homeserver::make_store_event_lookup`, `state_bookkeeping.cpp`, used by
`compute_state_before` and `recompute_current_state`), and `resolve_state_v2`
now computes ∪Ci − ∩Ci (the auth difference across the
submitted state groups' full auth chains) before selecting X.

Room v12 (state-res v2.1, `rooms::StateResolutionAlgorithm::v2_1`) makes three
further changes (rooms/v12.md — "State resolution"):

1. The iterative auth checks (Algorithm steps 2 and 4) start from an **empty**
   state map instead of the unconflicted state map.
2. A new **conflicted state subgraph** — the union of every path along
   `auth_events` edges between any pair of events in the conflicted state set,
   endpoints included — is computed.
3. The full conflicted set additionally includes that subgraph.

Modification 1 means almost nothing is present in the running state on the
first pass for a v12 room, so the iterative auth checks' own fallback matters
far more there: per the spec's "Iterative auth checks" definition, *"If a
(event_type, state_key) key that is required for checking the authorisation
rules is not present in the state, then the appropriate state event from the
event's `auth_events` is used if the auth event is not rejected."*
`build_auth_event_map_from_state` now implements this fallback for every
slot (create, power_levels, join_rules, sender/target member,
third_party_invite, authorising_user_member) — it did not before, which made
v12 support incomplete regardless of the algorithm-selection fix, since the
empty starting map meant almost every event's own auth context needed it.

**0.12.13 (ADR-0064 phase B2) fix: the create-event deadlock this fallback
cannot break for v12.** The fallback above reads a candidate event's OWN
`auth_events` when the running state lacks a key — but rooms/v12.md rule 3.2
requires every v12 event's `auth_events` to omit `m.room.create` (MSC4291:
the create event is implicit in the room ID). With modification 1's empty
starting map and no v12 event ever naming create in its own `auth_events`,
`build_auth_event_map_from_state`'s create slot could never be filled by
either path — every v12 candidate's very first iterative auth check would
fail Step 2 ("room has no create event"), and no v12 room's state could ever
be resolved at all. Fixed by seeding `resolved`'s `m.room.create` entry from
`unconflicted` at v2.1 initialization: a room's create event cannot
genuinely be in dispute (there is exactly one per room, and every submitted
state group already agrees on it — that agreement is precisely why
`partition_conflicted_state` places it in `unconflicted`, never
`conflicted`), so seeding just this one invariant entry does not reintroduce
anything modification 1's empty-start rule exists to guard against (mutable,
genuinely-contestable state like membership or power levels).

The auth-chain walk is bounded (`events::max_auth_chain_walk_events`,
`include/merovingian/events/limits.hpp`) and **fails closed**: a missing or
unreachable event, an over-budget walk, or an exhausted lookup returns an
unresolved `StateResolutionResult` rather than resolving on a partial chain —
`compute_state_before`/`recompute_current_state` (phase B1/B2, above) treat
an unresolved result as `PduIngestionStatus::missing_prev_state`, not a
rejection. This does not apply to the iterative auth checks' own `auth_events`
fallback above, which is intentionally soft — an ancestor it cannot reach
only fails that one candidate event's own auth check (as it already did
before the fallback existed), not the whole resolution.

Three properties of the ordering are easy to get subtly wrong and are worth
stating explicitly, because all three were defects (the first two until
0.12.9, the third until 0.12.13):

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
- **Sender power for the ordering comes from the candidate's OWN
  `auth_events`, never from the candidate's own new content and never from a
  shared state map.** Spec (rooms/v10.md — Reverse topological power
  ordering, rule 1): power is read "looking at their respective
  auth_events". Until 0.12.13, `power_level_from_event` read an
  `m.room.power_levels` candidate's sender power from **that same event's
  own new content** — a self-elevating power_levels event (one that grants
  its own sender a level it does not actually hold) would rank itself by
  the level it claims, not the level its own `auth_events` ancestor
  actually grants it. Every other candidate's power was read from a shared
  "unconflicted" state map, which is simply the wrong source: a candidate's
  `auth_events` can name a different `m.room.power_levels` event than
  whatever happens to be unconflicted at resolution time. Both cases are
  fixed by `find_auth_ancestor_context` walking the candidate's own
  `auth_events` (via the same fail-closed `AuthChainEventSource` used for
  the auth difference) and feeding the result to
  `events::effective_sender_power` (moved out of `authorization.cpp`'s
  anonymous namespace and exposed publicly, so the ordering and the auth
  rules read power identically, including MSC4289 creator-infinite power
  for room v12). `reverse_topological_power_sort` correspondingly takes
  `EventJsonIndex` + `EventLookupFn` instead of a `StateMap unconflicted`,
  and returns `optional<vector<StateEventReference>>` — `nullopt` when an
  `auth_events` entry needed to answer the question cannot be resolved
  (fail closed, ADR-0063), never a default value guessed from a partial
  chain. `mainline_order` was checked against the same defect class and
  found not to have it: it already reads each event's own `auth_events`
  power-levels ancestor (it never computes a power *level* at all, only a
  mainline *position*), never a shared map.

Event depth is persisted alongside the event row so ordering metadata survives
a server restart.

### Phase B1: state resolution wired into ingestion (ADR-0064)

Until 0.12.13's phase B1, `resolve_state_v2` was correct in isolation (see
above) but never ran on the production inbound-PDU path: `ingest_pdu_event`
(`src/homeserver/local_http_router.cpp`) authorised each PDU against current
state only and wrote its state straight into `current_state` — two
concurrent, individually valid state events resolved as whichever arrived
last, so resolved state could diverge from every other conformant server on
the same DAG depending on delivery order.

Phase B1 (`merovingian::homeserver::state_bookkeeping`,
`include/merovingian/homeserver/state_bookkeeping.hpp`) makes state
bookkeeping — not yet the receipt-order auth checks themselves, still B2 —
spec-conformant for every event stored through `ingest_pdu_event`:

- **State before an event** is the state resolution of the after-states of
  its `prev_events`: a single `prev_event` needs no resolution, several do.
  A `prev_event` with no recorded state group fails the PDU closed
  (`federation::PduIngestionStatus::missing_prev_state`) rather than
  guessing — the event is not stored, but per spec ("Transactions") a
  transaction containing it must still return 200, since a delayed but
  legitimate PDU looks identical to one whose history has not been fetched
  yet.
- **State after an event** is its state-before plus itself, if it is a
  state event.
- Every accepted event gets a delta state group for its after-state
  (`database::create_or_reuse_state_group`, ADR-0064 phase A) and updates
  the room's forward extremities.
- **Current state** is a cache of the resolution over the forward
  extremities, recomputed after each accepted event and diffed against the
  previous cache so only changed `(event_type, state_key)` entries are
  rewritten — through the same `database::store_state` every other state
  write already used, so `state_transitions` and the existing sync
  wake-up path need no separate "state changed" plumbing.

See `docs/database-persistence.md`, "Phase B1 of spec-conformant PDU
ingestion", for the exact functions. Phase B1 completion (same 0.12.13
branch) extended this same bookkeeping to every local event-creation path
(`homeserver::store_local_event`, the choke point `persist_composed_event`
now calls) and to federated-join state seeding
(`homeserver::record_event_state_with_parent`) — see that doc section for
the full list of call sites.

### Phase B2: the receipt-order auth checks themselves (ADR-0064)

Phase B1 made the state model correct; `ingest_pdu_event` still authorised
every inbound PDU against *current* state only, treated any auth failure as
a hard rejection, and rejected (rather than redacted) a content-hash
mismatch. Phase B2 runs the spec's six-step "Checks performed on receipt of
a PDU" in order (steps 1–2, format and signature, are unchanged — format
validation stays in `parse_inbound_pdu_envelope`/`authorize_federation_pdu`,
run before `ingest_pdu_event`; for a PDU relayed by a federation worker, main
re-verifies the signature itself before ingestion, ADR-0071):

- **Step 3 (hash).** `events::verify_pdu_content_hash` failing no longer
  rejects the event. `events::redact_event` (the room version's redaction
  algorithm) is applied and processing continues with the redacted form,
  which is the JSON that gets stored — `event_id`, `sender`, and every key
  the redaction rules preserve are unaffected, since redaction is exactly
  what the spec's reference-hash/event-ID derivation already treats the
  event as (v3+ event IDs never depended on the pre-redaction `content`
  anyway).
- **Step 4 (auth against the PDU's own `auth_events`).** Before running the
  auth-rule algorithm, `validate_auth_events_selection` enforces the spec's
  "Auth events selection" list — the permitted `(type, state_key)` pairs an
  event's `auth_events` may name (create unless v12-implicit, current
  power_levels, the sender's own member event, and for `m.room.member`
  additionally the target member, join_rules, third_party_invite, and the
  restricted-join authorising member, each conditioned on the requested
  membership). v12 (MSC4291, rooms/v12.md rule 3.2) is a hard **MUST NOT**:
  the create event is implicit in the room ID, and a v12 event naming it in
  `auth_events` is rejected, not merely warned about — this is enforced
  exactly as written, with no leniency for a "harmless" redundant reference.
  A named entry of a disallowed
  type, a duplicate `(type, state_key)`, or one from a different room is a
  rejection. An entry
  this store has no event for at all is `missing_prev_state` (the same
  "awaiting backfill" gap as a missing `prev_event`), not a rejection —
  phase C's fetch-then-request-state is what resolves it. Once selection
  passes, the auth map is built from the *named* events (fetched from the
  store), not current state — `build_pdu_auth_event_map` generalised to
  `build_auth_event_map_from_entries` so the same code builds this map, the
  state-before map, and the current-state map from whichever flat state
  snapshot each step needs.
- **Step 5 (auth against the state before the event)**, using phase B1's
  `compute_state_before`. Failure rejects, same as step 4.
- **Step 6 (auth against current state).** Failure here does not reject —
  spec "Soft failure": the event is stored, given an after-state group, and
  takes part in state resolution as normal, but it is never a forward
  extremity and never relayed to clients (see "Client-delivery filtering"
  below) — except that a soft-failed *state* event which resolution later
  admits into current state is shown to clients in the state section as
  usual.

**Rejected and soft-failed events are both stored** — this is the one place
phase B2 changes behaviour that was previously "at least safe": before this
phase, a step-4/5 auth failure returned early without persisting the event
at all, which broke the spec requirement that later events referencing a
rejected event can still be authorised against it. `record_event_state`/
`record_event_state_with_parent` (`state_bookkeeping.hpp`/`.cpp`) gained an
`accepted` flag (default `true`, so every phase-B1 caller is unaffected):
`false` still creates/reuses the event's after-state group and maps the
event to it (so `compute_state_before` can still resolve a later event's
`prev_event_ids` through it), but
`database::update_forward_extremities`'s own `accepted` gate (already
built for exactly this in phase B1's schema work) skips updating
extremities — neither a rejected nor a soft-failed event is ever a forward
extremity. What differs between the two is the after-state passed in: a
rejected event's after-state is `state_before` unchanged (spec: "state...
calculated as normal, except not updating with the rejected event"); a
soft-failed event's is the normally-computed `compute_state_after` result
(spec: "participate in state resolution as normal"), so a later accepted
event chaining off it correctly propagates its state through
`recompute_current_state` if resolution ever admits it.
`PersistentEvent::status` (`"accepted"|"rejected"|"soft_failed"|"outlier"`,
added in phase A but never set to the first two before this phase — the
0.12.12 security-audit finding that motivated this ADR) is set accordingly
at ingest time.

**Client-delivery filtering.** Every path that serves room timeline events
excludes `status == "rejected"` and `status == "soft_failed"`: `/sync`
(`client_server.cpp`), MSC4186 sliding sync
(`sync/sliding_sync_room_builder.cpp`), `GET .../messages`, `GET
.../context/{eventId}` (both its `events_before`/`events_after` window and
the target-event lookup, which 404s the same as a nonexistent event id),
`GET .../event/{eventId}` (same 404), and search. Current-state delivery
(the `/sync` `state` section, `required_state` in sliding sync) is driven
entirely by `current_state`/`recompute_current_state` and is untouched by
this filter, so a soft-failed state event resolution admits is still
delivered there. Federation-facing reads
(`src/federation/event_query.cpp`: `/event/<id>`, `/backfill`,
`/get_missing_events`) are deliberately unfiltered, matching the spec:
`/event/<id>` may return a soft-failed event, and `/backfill`/
`/get_missing_events` only return one when the request itself references
it — which those endpoints' existing depth/reference-driven scans already
satisfy without a status check.

**Transactions.** A transaction containing a mix of accepted, rejected, and
soft-failed PDUs still returns 200 with per-PDU accounting (spec: "If an
event in an incoming transaction is rejected, this should not cause the
transaction request to be responded to with an error response").
`PduIngestionStatus` gained `soft_failed`, threaded through the worker IPC
status mapping (`src/homeserver/worker_pool.cpp`,
`src/federation_worker/worker_event_loop.cpp`) and the `/send` transaction
per-PDU switch (`src/federation/inbound_request.cpp`) alongside the
existing `missing_prev_state`.

**Dead plumbing removed.** `PduStateConflictContext`,
`PduIngestionResult::state_conflict`, `StateConflictResolver`,
`ResolvedStateApplier`, `runtime.federation.state_conflict_resolver`, and
`federation::apply_state_resolution_v2` are gone — ADR-0064 identified them
as unreachable (nothing ever set `state_conflict`, so the resolver was
never invoked). `PduIngestionStatus::rejected_state_conflict` stays defined,
unused by any production sink, purely so the worker IPC wire format remains
a stable exhaustive set. `resolve_state_v2` itself is untouched: phase B1's
`compute_state_before`/`recompute_current_state` remain its only callers.

**Not covered by this phase.** The membership-acceptor path
(`send_join`/`send_leave`/`send_knock` acceptance) still hard-rejects a
content-hash mismatch instead of redacting, and does not run the
auth_events/state-before/current-state three-way check — see
`src/federation/AGENTS.md` and `docs/threat-model.md`.

### Phase C: backfill of missing PDU references (ADR-0064)

Phase C closes the gap left by phases A and B: an inbound PDU whose
`prev_events` or `auth_events` are unknown to this server is no longer
returned as `missing_prev_state` and forgotten. Instead, `ingest_pdu_event`
checks for missing references and, when the PDU envelope carries an origin,
fetches them from that origin before retrying the PDU.

* `collect_missing_pdu_references` distinguishes two failure modes:
  `auth_events` that are absent from the persistent store, and `prev_events`
  that are absent or exist but have no recorded after-state group. A
  `prev_event` without a state group cannot be used as a state-before anchor,
  so it is treated as missing.
* If any reference is missing, the room stripe lock and the runtime mutex are
  released (via `RuntimeLockRelease` and a scoped stripe-lock reacquirer) and
  `backfill_missing_pdu_references` performs outbound federation calls while the
  server remains unlocked for other rooms.
* The backfill strategy is `/_matrix/federation/v1/get_missing_events/{roomId}`
  first, then per-event `/_matrix/federation/v1/event/{eventId}`. The
  `/get_missing_events` call asks for up to 20 events; the whole PDU is allowed
  at most 5 outbound calls. These caps prevent a malicious or delayed origin
  from driving unbounded outbound work.
* Every fetched event is verified independently: content hash (mismatch
  redacts), Ed25519 signature, the `auth_events` selection check, and
  authorisation against its own `auth_events`. A fetched event whose own
  `prev_events` still lack state groups is dropped; its own state-before
  cannot yet be computed, so it cannot safely serve as an anchor for another
  event.
* A verified event is stored as `status == "outlier"` with a recorded
  after-state group (`accepted=false`). Outliers participate in later state
  resolution and can become `prev_events` for subsequent PDUs, but they never
  become forward extremities on their own.
* If a `prev_event` still has no state group, `backfill_state_ids_snapshot`
  asks the origin for `GET /_matrix/federation/v1/state_ids/{roomId}` at that
  event (at most 1000 IDs in each list, and its own budget of 100 outbound
  calls). Every named event not already stored is fetched and verified. A
  snapshot state event whose own `prev_events` have no state is verified
  instead through `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`,
  against its own `auth_events` only (ADR-0069). The snapshot is refused if it
  names an event from another room, a `rejected` event, a non-state event, or
  a duplicate `(type, state_key)`. The missing event is then authorised against
  the verified snapshot as its state-before.
* An event verified only against its own `auth_events` has an unknown
  state-before, so it is stored as an outlier **with no state group**
  (ADR-0070). A PDU that names it as a `prev_event` therefore triggers the
  `/state_ids` fallback at that event rather than being authorised against a
  state derived from the event's `auth_events`. Once a verified state before a
  stored group-less event is known and the event passes auth against it, it
  gains a state group and keeps its status.
* If references remain missing after the capped attempt, the original PDU still
  returns `missing_prev_state` and is not applied. Fail-closed is preserved;
  backfill only turns a *resolvable* gap into accepted history.

The membership-acceptor path does not yet run this backfill step — see the
`src/federation/AGENTS.md` residual note and the threat-model entry for phase C.

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
