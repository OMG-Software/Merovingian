# A join comes after the ancestors that share its depth

* Status: accepted
* Date: 2026-11-02

Technical Story: review of PR #549, capping depth (ADR-0314) let a join and the event it builds on share a depth

## Context and Problem Statement

ADR-0308 orders a join and an event by depth, on the footing that a join is always deeper than what it descends from,
and hides an event of equal depth as concurrent. ADR-0314 caps a composed event's depth at the room version's limit of
2^53-1, so in a room that has reached the limit a join and its ancestors have the same depth. Those ancestors were
hidden from a user the spec entitles to see them: under `shared`, the user "joined the room at any point after the
event was sent".

## Considered Options

* Walk back from the join when the depths tie, within a cap
* Keep hiding every event of equal depth
* Refuse to compose a join at the limit

## Decision Outcome

Chosen option: "Walk back from the join when the depths tie, within a cap". The comparison from ADR-0308 still decides
every other event, so rooms below the limit pay nothing and it stays one comparison per event. On a tie the event is
shown only if the walk reaches it. The walk runs once per room per request and stops at 500 events or below the join's
depth, and whatever it does not reach stays hidden, so concurrent events and the unresolved case both fail closed.

ADR-0308 rejected a walk as the rule for ordering because a cap hides long histories. That still holds, and this is not
that rule: it applies only to ties, where the alternative is hiding everything. Keeping the tie hidden was rejected
because it contradicts the spec for events that are not concurrent. Refusing the join was rejected because it would let
any server that can push a room to the limit stop users joining it.

### Positive Consequences

* A user joining a room at the depth limit sees the shared history behind their join, up to the cap.

### Negative Consequences

* Past 500 events at the limit, older ancestors stay hidden from a user the spec would show them to.
* The resident chooses the prev_events of a federated join, as ADR-0308 already notes for its depth. It already holds
  those events, and the former-member check from ADR-0311 still applies.
