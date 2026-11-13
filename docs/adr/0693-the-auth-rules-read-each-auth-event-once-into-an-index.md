# The auth rules read each auth event once, into an index

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit C16,
`F-resource-exhaustion.state-resolution.iterative-auth-checks-deep-copy-auth-events-per-candidate`. Refines
[ADR-0599](0599-one-resolution-reads-its-auth-graph-once-with-a-bit-per-group-not-a-closure-per-event.md).

## Context and Problem Statement

ADR-0599 bounded the auth-chain walks of one resolution, but the iterative auth checks still built an `AuthEventMap`
for every event of the full conflicted set by deep-copying the current create, power-levels, join-rules and member
events out of the resolved state, and the auth rules then walked those copies: the sender's level was a linear search
of `content.users`, every scalar a search of `content`, and rule 9 compared two power-levels events by searching one map
once per entry of the other. A remote room creator chooses both the number of conflicted events (up to 65,536) and the
size of the power-levels event (up to 64 KiB, about 2,000 users), so one resolution under `runtime.mutex` cost their
product.

How are the auth rules made to cost lookups per judged event, without changing a single decision?

## Decision Drivers

* A resolution's result must not change: this is a pure rewrite of how the rules read their inputs, and every
  existing auth and state resolution conformance test passes unchanged.
* The work of one resolution is linear in the distinct events it reads plus their sizes.
* Every caller of the auth rules shares one implementation of them.

## Considered Options

* Index each distinct auth event once (`IndexedAuthEvent`) and run the auth rules against indexes.
* Keep `AuthEventMap` and hold pointers into the resolved state instead of copies.
* A work budget per resolution (candidates times auth-event bytes) that fails closed.

## Decision Outcome

Chosen option: "Index each distinct auth event once", because it removes both per-candidate terms, the copy and the
searches, and leaves no other.

* `IndexedAuthEvent` borrows one event and reads it once: `sender`, `state_key`, each `content` member, the seven scalar
  power levels decoded with the room's encoding, `users`, `events` and `notifications` as hash maps with their levels
  also sorted, and `additional_creators` as a set. Every lookup answers what the same lookup on the JSON answers (the
  first member of a key; an undecodable level is absent).
* The auth rules run against `AuthEventIndexes` (`authorize_event_against_auth_indexes`).
  `authorize_event_against_auth_events` indexes its `AuthEventMap` and calls it, so every caller runs the same rules.
  An index built with another encoding than the room version's is refused, never read.
* The iterative auth checks keep one `IndexedAuthEventCache` per resolution, keyed by event ID: each distinct auth event
  is copied and indexed once (`StateResolutionResult::auth_events_prepared` counts them), and an entry never moves, so
  replacing an event in the resolved state cannot leave an index pointing at the replacement.
* Rule 9 indexes the candidate power-levels event too. 9.7 and 9.9 look each new entry up in the current event's index.
  9.6 and 9.8, which must find an entry changed or *removed*, count instead of walking: the current entries at or above
  the sender's level (from the sorted levels), less the sender's own for 9.8, less each entry the new event keeps
  unchanged. Anything left over was changed or removed. A 9.6 refusal no longer names the entry.

### Positive Consequences

* One resolution costs each distinct auth event's size once plus lookups per judged event. A power-levels candidate
  costs its own size plus a search, not the product of the two maps.
* Single-event authorisation reads each auth event once too (it walked them repeatedly before).

### Negative Consequences

* `authorize_event_against_auth_events` builds seven indexes per call, a hash map per object it reads. That is linear
  in the auth events, as before, with a larger constant.
* Rules that read the judged event itself (its content, its signatures) still walk it; that is linear in its own size,
  read once per check.

## Pros and Cons of the Options

### Keep `AuthEventMap` and hold pointers

* Good, because it is the smallest change.
* Bad, because the sender's level and rule 9 still search `content.users` per candidate, so the product stays.

### A work budget per resolution

* Good, because it also bounds siblings not yet found.
* Bad, because a refused resolution leaves current state unchanged (ADR-0375): a room with an honest large
  power-levels event would stop resolving, and the attacker chooses when.

## Links

* Refines [ADR-0599](0599-one-resolution-reads-its-auth-graph-once-with-a-bit-per-group-not-a-closure-per-event.md)
* Relates to [ADR-0375](0375-a-refused-recomputation-of-current-state-is-a-status-not-a-success.md)
