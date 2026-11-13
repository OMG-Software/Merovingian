# The badges of one event share one glob step budget

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C15 (resource-exhaustion.push-badge-count.row-budget-does-not-price-per-row-rule-evaluation)

## Context and Problem Statement

ADR-0608 bounds the badge work of one event to 10,000 event rows shared by all its recipients, and ADR-0607 bounds one
push-rule evaluation to 2^21 glob steps. The badge walk runs one full evaluation per row it visits, and each evaluation
built a fresh 2^21-step budget. The bound on rule work for one event was therefore 10,000 x 2^21 steps, held under
`runtime.mutex`, and a recipient who owns one wildcard rule and a room full of events with a 4,096-byte value under the
rule's key could make every notifying event take seconds.

## Decision Drivers

* The work under the runtime lock must be bounded by a constant per event, not by rows times a per-row constant.
* The badge is a lower bound whenever its walk is capped, and never counts more than `/sync` would (ADR-0207, ADR-0215).
* The evaluation of one event for notification (ADR-0343) keeps its own budget.

## Considered Options

* Lower the per-evaluation budget when the badge calls it
* Price each row at a fixed step cost and spend it from the row budget
* One `push::PushEvaluationBudget` shared by every classification of an event's badges

## Decision Outcome

Chosen option: "one shared budget". `PushBadgeBudget::glob` holds a `PushEvaluationBudget` (the former anonymous
`GlobBudget`, now public with the 2^21-step constant). `evaluate_push_rules` has an overload that draws from a caller's
budget, `PushRuleUnreadClassifier::use_evaluation_budget` lends it to every `classify`, and `count_push_badge` ends the
walk, `capped`, when it is spent. The row whose evaluation spent it is not counted: with a glob unaffordable, an
override rule could have been missed and a lower rule counted, which would over-count; ending the walk instead leaves a
lower bound.

The other caller of the badge walk in this area is the email digest (`EmailPush.cpp`, `prepare_email`), which counts under
one hold of `runtime.mutex` per due email. It takes a `PushBadgeBudget` per hold, so the same bounds apply to it: the rows,
and one 2^21-step glob budget over all of the walk's rule evaluations. The unbudgeted overload of `count_push_badge` builds
its own glob budget for the call, so no caller can run the walk with a fresh budget per row. Sync's unread counts call the
classifier per row too; they belong to another stream and are not changed here.

### Positive Consequences

* One event's badges spend at most 2^21 glob steps in total, however many rows or recipients.
* A recipient whose badge is capped by the budget reports a lower count, as for the row budget.

### Negative Consequences

* A recipient with several expensive rules can have an inexact badge number where before it was exact, but slow. The badge
  is an advisory count on a push notification; `/sync` counts remain exact.

## Pros and Cons of the Options

### Lower the per-evaluation budget

* Bad, because rows times any constant is still unbounded in rows, and it would weaken notification evaluation.

### Price rows at a fixed step cost

* Bad, because the cost of a row depends on the rules and the event, so a fixed price is either too low or starves honest
  badges.

## Links

* Refines [ADR-0607](0607-glob-conditions-on-every-key-share-the-per-evaluation-step-budget.md) and [ADR-0608](0608-the-badges-of-one-event-share-one-row-and-call-budget.md)
