# A backfilled event whose auth events fail is stored rejected, not dropped

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A8)

## Context and Problem Statement

ADR-0064 phase C dropped a backfilled event whose `auth_events` were not a permitted selection, named a rejected event, or denied it. Every later event naming it as a prev event then stayed unplaced and never reached `/sync`.

## Considered Options

* Store it with status `rejected` and an after-state equal to its state-before
* Keep dropping it

## Decision Outcome

Chosen option: "Store it with status `rejected` and an after-state equal to its state-before", because the spec's "Rejection" section keeps rejected events available for later events that reference them while they never change state. Signature and hash checks are unchanged and run first. An auth event that cannot be resolved at all is still a gap: the event is dropped and fetched again later.

### Positive Consequences

* Events built on a rejected event are placed.

### Negative Consequences

* A peer can make this server store rejected events, bounded by the same recovery budgets as accepted ones.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) (phase C)
