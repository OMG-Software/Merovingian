# A room remembers its last resolved state by its distinct state groups

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit,
`F-resource-exhaustion.state-resolution.every-accepted-pdu-resolves-all-distinct-extremity-states-under-runtime-mutex`.
Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) and
[ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md).

## Context and Problem Statement

Every accepted PDU recomputes current state over the room's forward extremities, with `runtime.mutex` held. A message adds
no state, so it usually leaves the room's distinct state groups exactly as they were, yet the recomputation resolved them
all again, and parsed each stored event once for every group naming it. A room with many standing forks cost that much per
message.

State groups are immutable, so resolving the same groups must come to the same answer. The saved work must not change what
is written, or who else may write `current_state` (ADR-0225, ADR-0373).

## Decision Drivers

* A PDU that changes nothing to resolve must not cost a resolution.
* Whatever else wrote `current_state` since the last resolution behaves as it does today.
* A resolution also reads what is not in a group: each event's JSON and status.
* Nothing under the lock may grow without bound.

## Considered Options

* Skip the recomputation when a PDU leaves the set of groups unchanged.
* Remember the resolved entries and still apply them through the normal write path.
* Remember per event in the store, across recomputations, the parsed references.

## Decision Outcome

Chosen option: "Remember the resolved entries and still apply them through the normal write path".

`ResolvedStateMemo` holds one entry per room: the sorted distinct state group IDs, a context string (the room version and
every limit that can change a result), and the resolved entries. `resolve_extremity_states` asks it once the distinct
groups are known and within `max_state_groups`. A hit returns the entries and the caller diffs and writes them exactly as
for a fresh result.

* **Only a success is remembered.** A refusal is resolved again every time, as before, because a later arrival can end it.
  An event a resolution needs and cannot find is a refusal, so a remembered result never depended on an absent event.
* **Invalidation.** `set_event_status`, `replace_event_json` and `apply_room_snapshot` forget the room, since a resolution
  reads each event's status and JSON. A later writer of either must do the same.
* **Order in `store_event_with_bookkeeping`.** A fresh result is remembered after the commit and before the event is
  applied. Applying a redaction overwrites its target and forgets the room; remembered afterwards, a result read from the
  unredacted target would outlive it.
* **Bounds.** At most 256 rooms and 131072 rows in all, least recently used first, and a result over the row limit is not
  kept. In memory only.
* **Locking.** It has no lock: it is reached only with `runtime.mutex` held. `find` is non-const because it updates the
  recency, so it cannot be reached through a `const` store (ADR-0525).

Within one recomputation a lookup parses each stored event once, however many groups name it. The cache lives for that one
call, so it needs no invalidation.

### Positive Consequences

* A message in a room with K standing forks parses no stored event, whatever K is.

### Negative Consequences

* Computing the key still walks the tips by hash lookup, with no parse.
* Each room costs memory for one resolved state, within the bounds above.

## Pros and Cons of the Options

### Skip the recomputation when a PDU leaves the set of groups unchanged

* Good, because it is less code and does no diff at all.
* Bad, because `current_state` has other writers: each accepted state event's own row and the ADR-0225 fallback. Skipping
  would leave what they wrote where today the next recomputation corrects it.

### Remember per event in the store, across recomputations, the parsed references

* Good, because it would also help when the set of groups does change.
* Bad, because it keeps parsed JSON for as many events as remote servers name, and every redaction must find its entries.
  Parsing once per recomputation gets the bound the finding asks for without that.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
* Refines [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md)
