# A refused recomputation of current state is a status, not a success

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-49
(`state.recompute-refusal-reports-success-leaves-unresolved-current-state`).

## Context and Problem Statement

`recompute_current_state` returned `true` when it could not resolve the room's forward extremities
(more than `max_state_groups`, the state budget, an extremity with no readable state, a resolution
that fails closed), and `store_event_with_bookkeeping` substituted an empty resolution for the same
case. The header called it "a defensive fallback for degenerate input, not an expected runtime path".
A remote member can reach it, and in a very large room it happens with no attacker. Callers had no
signal, and nothing was logged for the count and budget cases.

What should a refusal do, and what should current state be while it lasts?

## Decision Drivers

* A refusal must be visible to the caller and logged at warning level.
* While the extremities cannot be resolved, a ban or a demotion that arrives must still take effect.
* No result may be invented: current state is never set to a state nothing derived.

## Considered Options

* Return a status and leave `current_state` as it is, plus each accepted event's own row.
* Freeze `current_state` while refused: accepted events write no row.
* Resolve a bounded subset of the extremities, chosen by stream order, while refused.
* Treat a refusal as a failure of the PDU (reject or defer it).

## Decision Outcome

Chosen option: "Return a status and leave `current_state` as it is".

`recompute_current_state` returns a `CurrentStateRecompute`: `resolved`, `refused` (with a reason) or
`write_failed`. Its `explicit operator bool` is true only for `resolved`, so a caller that treats it
as success no longer does on a refusal. A refusal logs `state.current.refused` at warning level with
the room and the reason; `ingest_pdu_event` and the membership acceptor log which event they were
placing. `store_event_with_bookkeeping` returns `resolution_refused` and the reason in
`StoredWithBookkeeping`, and logs the same event. An empty extremity set is `resolved`: nothing to
resolve. The header comment no longer calls it a degenerate path.

While refused, current state is what it was plus the own row each accepted event writes. That path is
kept on purpose: a ban that arrives while the tips cannot be resolved must still apply, and freezing
current state would let the banned user's next events pass the step 6 check. It is not made worse by
the bound of ADR-0374, which removes the cheap trigger.

### Positive Consequences

* A caller cannot mistake a refusal for success; operators see it.
* A ban that arrives while the tips cannot be resolved still applies (freezing would drop it).

### Negative Consequences

* Residual: while a refusal lasts (the state budget in a very large room, or a member's distinct state
  tips past `max_state_groups`), a state event that resolution would have reverted can stay current,
  and the own-row write is last-accepted-writer-wins. This needs an accepted state event per tip, or a
  room whose state exceeds the budget, and it ends when the tips are back within budget and the next
  accepted event resolves them (a local event cites up to 20 and retires them).
* The own-row path is not a resolution. Making it one means resolving only the new event against the
  current holder of its key, which needs the auth difference and is not done here.

## Pros and Cons of the Options

### Freeze `current_state` while refused

* Good, because current state could not take a stale state event's row.
* Bad, because it also drops a ban or a demotion, which is worse than the stale write it prevents.

### Resolve a bounded subset by stream order

* Good, because resolution would run.
* Bad, because the subset is the newest tips, and older ones, which can hold the revocation, fall
  out; the recompute then writes the older state over it. Chosen by a sender's timing.

### Treat a refusal as a failure of the PDU

* Bad, because the PDU is valid and already stored; failing it only causes pointless retries.

## Links

* Related: [ADR-0373](0373-a-fallback-event-records-the-rooms-current-state-as-its-state-before.md), [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md)
* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
