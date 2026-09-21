<!-- items marked as optional *are* optional => consider whether they are useful before filling them -->
# Fail closed when the state-res v2/v2.1 auth-chain walk cannot reach an event

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-22

Technical Story: HIGH-severity conformance bug — `resolve_state_v2` never
computed the auth difference or (for room v12) the conflicted state
subgraph, so power events reachable only through a conflicted event's
`auth_events` chain were invisible to the resolver, letting resolved state
diverge from conformant servers.

## Context and Problem Statement

The Matrix spec's state-res v2 Algorithm (rooms/v10.md) selects candidates
from the *full conflicted set* — the conflicted state set plus the *auth
difference* (∪Ci − ∩Ci, where Ci is the full auth chain of each state
group). Computing this requires walking `auth_events` chains for events that
are not necessarily present in either of the two state snapshots the
resolver was handed — they must be fetched from wherever the room's full
event graph actually lives (the persistent store, in production).

That walk can fail partway through: an ancestor event might not be in the
lookup's source at all (a store missing an event it should have, or an
adversarial/incomplete state group), or the walk might be cut off by the
resource cap (`events::max_auth_chain_walk_events`) before it completes. The
question is what the resolver should do when that happens: resolve using
whatever partial chain information it does have, or refuse to produce a
result at all.

## Decision Drivers

* State resolution is reachable from untrusted federation input — a hostile
  or buggy remote server can propose a state fork whose auth chain is
  deliberately incomplete, deep, or wide.
* A wrong resolved state is worse than no resolved state: silently resolving
  on a partial auth chain can under-count or over-count power events,
  reintroducing exactly the divergence-across-servers risk this fix closes.
* The caller (`federation::apply_state_resolution_v2`) already has a defined
  fallback for "resolution failed" — `rejected_state_conflict`, which drops
  the PDU and audits the conflict — so failing the resolution is not a dead
  end operationally.

## Considered Options

* Resolve using the chain information available, treating unreachable
  ancestors as simply absent from the full conflicted set.
* Fail the whole resolution (`StateResolutionResult::resolved = false`)
  whenever an event needed for the auth-chain walk cannot be fetched, or the
  walk's work budget is exceeded.

## Decision Outcome

Chosen option: fail closed. `resolve_state_v2` returns an unresolved result
whenever the auth-difference computation, the v12 conflicted-state-subgraph
computation, or the "enlarge X" auth-chain walk in Algorithm step 1
encounters a missing/unreachable event or exceeds
`events::max_auth_chain_walk_events`. The caller maps this to
`rejected_state_conflict`, the same outcome as any other state-res failure.

This applies specifically to the three walks above — the ones that determine
*membership* of the full conflicted set. It deliberately does **not** apply
to the iterative auth checks' own separate `auth_events` fallback (used when
a required `(event_type, state_key)` is not present in the running resolved
state — spec: "Iterative auth checks"): an unreachable ancestor there only
causes that one candidate event to fail its own auth check, exactly as it
already did before the fallback existed. Failing the entire resolution over
one candidate's missing context would be a strictly worse regression for
ordinary, non-adversarial gaps (e.g. a server that has not yet backfilled one
old event) than simply not applying that one event.

### Positive Consequences

* No silent, non-conformant resolution: two servers with different views of
  the same room's history either agree on the eventual full conflicted set,
  or both refuse to resolve and fall back to the existing conflict-audit
  path, rather than one of them (the one with less history) quietly
  producing a different answer.
* The failure mode was already load-bearing: `apply_state_resolution_v2`
  already had a defined "resolution failed" outcome before this change, so
  no new caller-side handling was required.

### Negative Consequences

* A server with an incomplete event graph for a room (e.g. mid-backfill) can
  now have PDUs it would previously have accepted (on a — possibly wrong —
  best-effort resolution) rejected instead, until backfill catches up. This
  is treated as acceptable: an accepted-but-wrong resolution is a worse
  failure mode for a consensus algorithm than a rejected PDU that can be
  retried once backfill completes.

## Links

* Implements: Matrix spec v1.19, rooms/v10.md — Definitions ("Auth chain",
  "Auth difference", "Full conflicted set"), Algorithm step 1.
* Implements: Matrix spec v1.19, rooms/v12.md — Definitions ("Conflicted
  state subgraph"), "State resolution".
* Related: `docs/event-engine.md` — "Auth difference, full conflicted set,
  and the v12 conflicted state subgraph".
