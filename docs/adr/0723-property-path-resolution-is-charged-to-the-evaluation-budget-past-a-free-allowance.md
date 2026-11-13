# Property path resolution is charged to the evaluation budget past a free allowance

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C25 (resource-exhaustion.push-rules.property-path-resolution-scans-unbudgeted)

## Context and Problem Statement

ADR-0607 charges glob steps and array scans to the per-evaluation budget, but every `event_match`, `event_property_is`
and `event_property_contains` condition first resolved its key with a function that split the path into new strings and
found each segment by a linear scan of the event's object members, none of it charged. A recipient with 200 rules of 16
conditions and a sender whose event holds about 8,000 content keys made one evaluation do about 2.6 x 10^7 member
compares under `runtime.mutex`, per recipient per event, and again per row in badge and unread walks.

## Decision Drivers

* The default rules must keep working when the budget is spent (ADR-0607: `event_property_is` was never refused).
* A sender chooses the width of the event; the recipient chooses the number of conditions.

## Considered Options

* Charge every member scanned
* Parse each rule's key into segments once at load, and charge nothing
* Charge the members scanned past a free allowance of 64 per object, and decode the path without a vector

## Decision Outcome

Chosen option: the third. `resolve_event_property` takes the evaluation's `GlobBudget` and charges
`members - 64` (zero when fewer) before each segment's scan, returning no match when the budget cannot pay. It decodes one
segment at a time into one string. The fixed top-level reads the evaluator makes once per evaluation (`sender`,
`room_id`) are not charged and `room_id` is read once, not per room rule.

### Positive Consequences

* One evaluation spends at most the shared glob budget on path scans: a very wide event stops matching rules whose
  conditions would scan it, after about 260 scans of 8,000 members.
* An ordinary event (a few dozen members per object) costs nothing, so the default ruleset behaves as before even with the
  budget spent by an earlier rule.

### Negative Consequences

* A key path into an object with more than 64 members is charged, so a legitimate event with a very wide `content`
  can lose a rule match once the budget is spent. Such events are what the budget exists for.

## Pros and Cons of the Options

### Charge every member scanned

* Bad, because with the budget spent no condition could resolve, so even the default rules would stop matching.

### Pre-parse the key and charge nothing

* Bad, because it removes only the allocation; the scan of sender-chosen members is the cost.

## Links

* Refines [ADR-0607](0607-glob-conditions-on-every-key-share-the-per-evaluation-step-budget.md) and [ADR-0722](0722-the-badges-of-one-event-share-one-glob-step-budget.md)
