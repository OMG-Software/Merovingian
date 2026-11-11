# Glob conditions on every key share the per-evaluation step budget

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, push-rules.event-match-glob-on-non-body-keys-unbudgeted

## Context and Problem Statement

[ADR-0343](0343-push-glob-matching-spends-a-bounded-budget-per-event.md) bounds the glob matching of
`content.body` and says rules on other keys "are unaffected". An `event_match` on any other key ran an
unbudgeted O(value x pattern) matcher after copying and lowercasing the whole value. A user with 200 rules
and a second account that sends a 60 KB string field could hold `runtime.mutex` for seconds per event.

## Considered Options

* Charge a worst-case value x pattern cost up front and cap the value to a prefix, as the audit proposed
* Charge the matcher one step per turn of its loop, and refuse a value over a cap
* Leave other keys alone, because identifiers are short

## Decision Outcome

Chosen option: charge per step and refuse an over-long value.

* `glob_matches_full` takes the evaluation's `GlobBudget` and charges one step per turn. A glob that runs
  out of budget does not match and the result carries `glob_budget_exhausted`, as for the body.
* It compares ASCII case-insensitively without copying value or pattern, and
  `event_property_as_string` returns a view, so the value is not copied before any bound applies. The same
  applies to `content.body`, `sender` and `room_id`.
* A pattern without a wildcard checks the lengths first and costs one step per byte only when they are equal.
* A pattern with a wildcard does not match a value over `max_push_glob_key_value_bytes` (4096).
  This is a deliberate departure from the spec, which matches the entire value: the whole value cannot be
  judged on a prefix, as `content.body` can (a body match is "any substring", so a prefix is a sound
  search window). No Matrix identifier, type or msgtype approaches 4096 bytes. Even a pattern of only `*` does not match
  such a value; special-casing it was rejected as complexity for a case no rule needs.
* `event_property_contains` charges one step per array element before it scans, and `event_property_is`
  one step. Both do plain scalar compares, but the sender chooses the array length and the recipient the
  number of conditions.

Charging the worst case up front was rejected: one 4096-byte value against a 510-byte pattern would cost
about 2 million steps, the whole budget, for a rule that matches in a few steps.

### Negative Consequences

* A wildcard rule on a string field longer than 4096 bytes never matches. Exact (wildcard-free) patterns are unaffected.
* Step counts from `content.body` and other keys share one budget, so a recipient with many expensive
  rules loses the later ones for that event, and the operator sees `push.glob_budget.exhausted`.

## Links

* Refines [ADR-0343](0343-push-glob-matching-spends-a-bounded-budget-per-event.md)
