# A fallback event records the room's current state as its state before

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-40
(`state.new-event-fallback-rewrites-current-state-from-attacker-chosen-fork`). Supersedes the
state-before and consequence wording of [ADR-0225](0225-a-local-event-falls-back-to-the-newest-forward-extremity-when-their-state-cannot-be-resolved.md);
the rest of ADR-0225 (cite one extremity, retire the others, warn, refuse only when none reads) stands.

## Context and Problem Statement

ADR-0225 lets a local event cite the newest readable forward extremity when the state across all of
them cannot be resolved, and retire the others. It said the event's state before is that
extremity's after-state, accepted that a retired fork's ban or power change "stops being reflected"
until a descendant arrives, and said a remote server "can only steer which accepted fork is cited".
Three of those premises were wrong:

* Storing the event left one extremity, so `store_event_with_bookkeeping` took that fork's state as
  the resolved state and wrote every entry that differed into `current_state`. A fork that predates
  a ban carries the banned user's old join, so the write undid the ban in current state.
* The extremity is chosen by this server's stream order, which a remote sender influences by when it
  sends, and the failure can be forced by a member (a budget of 20 forks in a room of 6554 state
  events, or a stored non-state event named as an auth event; the latter was closed by F-05).
* The damage does not recover. Every accepted inbound PDU runs `recompute_current_state`, which with
  one extremity writes that extremity's whole state group, so the old join came back on the next
  PDU even if the diff write in `store_event_with_bookkeeping` was suppressed. The banned user's
  next PDU then passed steps 4 to 6 and was stored as accepted.

What state should a fallback event record, so that nothing about a revocation depends on which
fork it happened to cite?

## Decision Drivers

* The spec defines current state as the state resolved across all forward extremities, and soft
  failure relies on it to discourage events that evade a ban (server-server-api.md, "Soft failure").
* A failure to resolve must not replace accepted current state with one unresolved branch.
* The invariant has to hold in the state the fallback event records, not only in the write made when
  it is stored, because the group it records is what every later single-extremity recompute reads.
* A user must still be able to leave and to keep talking in a room whose forks do not resolve
  (ADR-0225's driver), and one bad fork must not cost a failing resolution on every local event.

## Considered Options

* Build the fallback event's state before from the room's cached `current_state`.
* Suppress the `current_state` diff write for a fallback event.
* Keep the retired tips as forward extremities (ADR-0225's rejected option), bounding the repeated
  resolution another way.
* Refuse the local event.

## Decision Outcome

Chosen option: "Build the fallback event's state before from the room's cached `current_state`".

`basis_for_new_event` still cites the newest readable extremity in `prev_events` (stream order, not
`depth`) and retires the others, so the failing resolution is not repeated. When it falls back, the
returned `state_before` is the room's `current_state`, read in one pass over the room's rows
(`for_each_room_state_row`), and not that extremity's group. `current_state` still holds the
revocation: it is the cache `recompute_current_state` left alone when it refused. The fallback event's
state group, built from it, keeps the revocation, so the diff in `store_event_with_bookkeeping` writes
nothing beyond the event's own row, and every later single-extremity recompute writes entries equal to
what is already there. A room with no `current_state` row at all (degenerate: every room has its create
event) uses the extremity's own state, as before.

The event's `auth_events` already come from `current_state` (`auth_events_for_room`), and the local
authorization check reads it too, so the event's auth events are now all in its own state before; with
the old basis they could name an event its recorded state lacked. The log line
`event.prev_events.fallback` gains `state_before` (`current_state` or `prev_event`).

### Positive Consequences

* A fork that predates a ban or demotion cannot restore it through a local event, nor through the
  next inbound PDU. A banned user's next PDU is judged against the ban at steps 5 and 6.
* The fallback is unchanged for the cases ADR-0225 was written for (a leave, a message).

### Negative Consequences

* The recorded state before no longer equals what a peer derives from `prev_events` alone. For the
  cited fork `C`, a peer computes state(C); this server records current_state plus the event. The two
  agree when `current_state` is the resolution of every extremity, and differ by exactly what the
  retired tips (and unresolved writes) contributed. A server that fetches this event from us and
  computes its own state before gets the fork's state; each server judges the event it receives by
  its own computation, and the event is a local, valid message or state change under current state.
* `current_state` is itself a cache and, while a recompute is refused (ADR-0375), the accepted events'
  own rows. A fallback event inherits that. It does not make it worse than the room already was.
* A local event stored on a retired fork's descendant (an inbound PDU citing the retired ban tip) is
  judged against that tip's own state and then resolved against this event's group; both contain the
  ban, so they do not conflict on it.
* Reading `current_state` costs one pass over the room's state rows, the same order as reading a
  state group, under `runtime.mutex`, and only when the fallback is taken.

## Pros and Cons of the Options

### Suppress the `current_state` diff write

* Good, because it is a small change to `store_event_with_bookkeeping`.
* Bad, because the event still records the fork's state group, and `recompute_current_state`, which
  runs after every accepted inbound PDU, writes that group's entries when it is the only extremity.
  The next PDU restores the old join. The invariant would hold for one write and fail on the next.

### Keep the retired tips as extremities

* Good, because the ban tip stays in the resolution.
* Bad, because every later local event repeats the failing resolution under the lock, as ADR-0225
  found, and an attacker keeps the failure alive by adding forks.

### Refuse the local event

* Bad, because it is the 500 on leave that ADR-0225 removed.

## Links

* Supersedes the state-before and consequence wording of [ADR-0225](0225-a-local-event-falls-back-to-the-newest-forward-extremity-when-their-state-cannot-be-resolved.md)
* Related: [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md), [ADR-0375](0375-a-refused-recomputation-of-current-state-is-a-status-not-a-success.md)
