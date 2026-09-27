# Spec-conformant PDU ingestion with delta state groups

* Status: accepted
* Date: 2026-09-22

Record note: this ADR previously named "Deciders: James Chapman", which was
not accurate; the line was removed on 2026-09-27. The date is the ADR's first
commit (`42e80be9`).

Technical Story: 0.12.13 security audit. State resolution v2 was fixed
(ADR-0063) but never ran in production: nothing set
`PduIngestionResult::state_conflict`, so `state_conflict_resolver` was
unreachable.

## Context and Problem Statement

`ingest_pdu_event` (`src/homeserver/local_http_router.cpp`) authorised each
inbound PDU against the room's *current* state only, then wrote state events
straight into `current_state`. Two concurrent, individually valid state events
therefore resolved as "whichever arrived last". Every spec-conformant server
resolves them deterministically, so our room state could diverge from the rest
of the federation, and a peer that controls delivery order could choose which
one we kept.

The spec requires six checks on receipt, in order (server-server-api.md,
"Checks performed on receipt of a PDU"): event format, signatures, hashes
(mismatch: **redact**, not reject), auth against the event's own
`auth_events` (reject), auth against the state *before* the event (reject), and
auth against the current state (soft-fail). The store had none of the
machinery this needs: no per-event state, no forward-extremity tracking, and no
record of which events were rejected or soft-failed. A seventh check, Policy
Server validation (v1.18), is out of scope here and tracked separately.

How do we make inbound PDUs follow the spec without trusting a remote server's
word about room state?

## Decision Drivers

* The spec is the authority. Resolved state must be identical to every other
  conformant server's for the same DAG, or the room partitions.
* Everything on this path is driven by untrusted remote input, so every walk,
  fetch, and resolution must be bounded and must fail closed.
* A remote server's claim about historical state (`/state_ids`) must never be
  used without verifying each event it names.
* Storage must stay proportionate for large public rooms (tens of thousands
  of members, frequent membership changes).

## Considered Options

### State before an event when prev_events are missing

1. **Fetch, then request state (chosen).** `/get_missing_events` (bounded),
   and if a gap remains, `/state_ids` + `/event_auth` from the sending server,
   verifying every returned event before use.
2. Fetch only, otherwise hold the PDU as an unresolved outlier until the gap
   fills.
3. Fetch only, otherwise reject the PDU.

### Per-event state storage

1. **Delta state groups (chosen).** Each group stores only its changes from a
   parent group, with a full snapshot every `max_state_group_delta_depth`
   levels to bound lookup cost.
2. Full snapshot per state change.

### Current state

1. **Resolution over forward extremities (chosen).**
2. Last writer wins (the status quo).

## Decision Outcome

Chosen: fetch-then-request-state, delta state groups, and current state as the
state resolution over the forward extremities. Option 1 is the only one that
keeps us in consensus when history is delayed or unreachable. Options 2 and 3
stall or partition us from rooms whose history we cannot reach, and the status
quo is the defect itself.

### How it works

* **Receipt order.** Checks run in spec order. A hash mismatch redacts the
  event (spec step 3) and processing continues with the redacted form. A
  failure at step 4 or 5 marks the event `rejected`: it is stored so later
  events that reference it can still be authorised, but it never updates
  state, never becomes a forward extremity, and is never sent to clients. A
  failure only at step 6 marks it `soft_failed`: it is stored and takes part
  in state resolution, but is excluded from forward extremities and client
  timelines. A soft-failed *state* event that state resolution admits into the
  current state is shown to clients in the usual way, as the spec says.
* **State before an event** is the state resolution of the states after each
  of its `prev_events`. With a single prev_event it is that event's state
  after, with no resolution needed. The state after an event is the state
  before it plus the event itself, if it is an accepted state event.
* **Missing prev_events.** `/get_missing_events` up to a bound on events and
  depth. If a gap remains, the server fetches `/state_ids` and `/event_auth`
  at the event from the server that sent the PDU, fetches any events it lacks,
  and runs signature, hash, and auth checks on every one (each against its own
  auth_events) before the set is used as state. An event that fails is
  dropped from the claimed state. If the claimed state cannot be verified, the
  PDU is rejected, never applied on unverified data. All outbound fetches per
  PDU and per transaction are capped.
* **State groups.** An event that does not change state shares its parent's
  group. A delta chain longer than the snapshot depth starts a new full
  snapshot. Group creation is part of the same transaction as the event.
* **Current state** is recomputed after each accepted event from the forward
  extremities (accepted, non-soft-failed events with no accepted children),
  and `current_state` becomes a cache of that result, never an independent
  write target.
* **Local events** take their `prev_events` from the forward extremities.
* **Existing rooms** are seeded by a migration: each room's current
  `current_state` becomes a snapshot group attached to its current extremity
  events. Older events have no recorded state and are treated as outliers for
  any later resolution that reaches them.

### Positive Consequences

* Our resolved state matches every conformant server's for the same DAG.
* Ban evasion through old parts of the DAG is soft-failed, not accepted into
  client timelines.
* Delivery order no longer decides room state.

### Negative Consequences

* The ingest path makes outbound federation requests (missing events, state).
  They are bounded, but ingestion latency for a PDU with a gap now includes
  round trips to its origin.
* `/state_ids` state claimed by the origin is trusted once every event in it
  passes its own checks. A malicious origin can still omit events it is
  entitled to omit. State resolution against other forks limits the damage,
  which is the same residual risk every conformant server accepts.
* The schema grows (state groups, extremities, event status), and a one-time
  seeding migration runs on upgrade.

## Pros and Cons of the Options

### Hold as outlier until the gap fills

* Good, because no remote claim about state is ever used.
* Bad, because a room whose history we cannot reach stalls indefinitely, and
  other servers carry on without us.

### Reject when unresolvable

* Good, because it is the simplest.
* Bad, because it drops legitimate delayed events and partitions us from the
  room: the spec is explicit that delayed events are indistinguishable from
  malicious ones and must be accepted.

### Full snapshot per state change

* Good, because reads are one lookup and the code is simple.
* Bad, because storage grows with state size × number of state changes, which
  is quadratic-ish for large public rooms with membership churn.

## Phase C: backfill of missing `prev_events` and `auth_events` (shipped — `/state_ids` fallback added in 0.12.13)

The decision above selected "fetch, then request state". Phase C implements that
option for the inbound `/send` path in `ingest_pdu_event`
(`src/homeserver/local_http_router.cpp`):

* Before a PDU is accepted, `collect_missing_pdu_references` finds `auth_events`
  that are absent from the store and `prev_events` that are absent or have no
  recorded after-state group.
* If any are missing and the envelope carries an `origin`, both the room
  stripe lock and the runtime mutex are released and
  `backfill_missing_pdu_references` fetches them from the sending server.
* A single `POST /_matrix/federation/v1/get_missing_events/{roomId}` call is
  tried first, asking for up to `k_max_get_missing_events_per_pdu` (20) events
  between the PDU's `prev_events` and the missing ones. Remaining missing
  `auth_events` and `prev_events` are then fetched individually via
  `GET /_matrix/federation/v1/event/{eventId}`. The total number of outbound
  calls a single PDU can trigger is capped at
  `k_max_backfill_outbound_calls` (5); once the cap is reached the backfill
  attempt stops and any still-missing references cause the PDU to return
  `missing_prev_state`.
* Every returned event is verified independently before it is used: content
  hash (a mismatch redacts the event and processing continues with the
  redacted form), Ed25519 signature via the remote-key resolver, the
  `auth_events` selection check, and authorisation against its own
  `auth_events`. Events whose `prev_events` still lack state groups are dropped,
  because their state-before cannot be computed yet.
* A verified event is stored with `status == "outlier"` and a recorded
  after-state group (`accepted=false`). Outliers take part in later state
  resolution but never become forward extremities on their own.
* After backfill returns, `ingest_pdu_event` reacquires the locks and rechecks
  the same PDU. If references remain unresolvable, the PDU is returned as
  `missing_prev_state` and is not applied — fail-closed rather than accepting
  on unverified data.

### Phase C2: `/state_ids` fallback for gaps `/get_missing_events` cannot fill

When `/get_missing_events` returns nothing useful and a `prev_event` still lacks
a recorded state group, `backfill_missing_pdu_references` falls back to
`GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...` on the sending
server. The response's `pdu_ids` and `auth_chain_ids` are capped (1000 each);
if either cap is exceeded the snapshot is rejected. Every named event that is
not already in the store with a state group is fetched via
`/event/{eventId}` and verified independently — content hash, signature,
`auth_events` selection, and auth against its own `auth_events`. A snapshot event
that fails verification causes the whole snapshot to be rejected, because a
partial or forged snapshot must not be used as state. The verified state
events in `pdu_ids` form the snapshot; the missing `prev_event` is then fetched
and authorised against that snapshot as its state-before, bypassing the usual
requirement that its own `prev_events` have recorded state groups. The target
event is stored as an outlier with an after-state group derived from the
snapshot. This completes the "fetch, then request state" option: the snapshot
is accepted only after every event it names has been verified, never on the
remote server's word alone.

This bounds the work a malicious or delayed origin can drive: an inbound PDU
with a gap cannot trigger more than five outbound federation calls or fetch
more than twenty events through `/get_missing_events`. The `/state_ids`
fallback adds caps on response size and on the number of snapshot events we
will materialise (1000), with its own budget of 100 outbound calls
(ADR-0069). An event verified there only against its own `auth_events`
carries no recorded state (ADR-0070). The rejected alternatives — hold the PDU indefinitely
or reject it outright — are documented above under "Pros and Cons of the
Options"; they would partition the server from rooms whose history arrives late
or via a different path.

## Links

* [ADR-0063](0063-fail-closed-on-unreachable-state-res-auth-chain-events.md)
  (fail closed on unreachable auth-chain events; the walk cap)
* server-server-api.md: "Checks performed on receipt of a PDU", "Rejection",
  "Soft failure", "Backfilling and retrieving missing events"
