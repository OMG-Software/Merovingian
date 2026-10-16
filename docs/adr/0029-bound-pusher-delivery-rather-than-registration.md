# Bound pusher delivery rather than registration

* Status: accepted; registration part superseded by [ADR-0151](0151-cap-pusher-registration-and-break-the-circuit-to-failing-gateways.md) (2026-10-15)
* Date: 2026-09-06

## Context and Problem Statement

A recipient can register unbounded pushers, and every notify-worthy event
processed a recipient's entire pusher list sequentially inside one background
task — potentially occupying an in-flight delivery slot for minutes or hours.

## Considered Options

* Bound how many pushers are contacted per delivery
* Bound how many pushers a user may register

## Decision Outcome

Chosen option: "Bound how many pushers are contacted per delivery".
`k_max_pushers_per_delivery` (10) truncates the list actually contacted per
event, logging when it truncates. `POST /pushers/set` stays unbounded and
unchanged.

Bounding registration would be a visible, spec-adjacent behaviour change for
clients; bounding delivery is invisible except under abuse.

### Negative Consequences

* A user with more than ten pushers has some of them silently skipped for a
  given event, and which ten depends on list order.
* The underlying unbounded registration remains, so the memory cost of a large
  pusher list is unchanged — only the delivery cost is bounded.

## Links

* `CHANGELOG.md`, 0.11.11

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
