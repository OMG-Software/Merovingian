# Document inert configuration keys rather than removing them

* Status: accepted for `database.migration_role`; superseded by [ADR-0498](0498-a-documented-configuration-key-is-enforced-or-removed-and-redaction-keys-only-accept-true.md) for `allowed_bind_domains`
* Date: 2026-09-06

## Context and Problem Statement

Two configuration keys are parsed, validated and reload-classified but enforce
nothing. `database.migration_role` does not narrow the privileges migrations
run with beyond assuming the role, and
`server.identity_server.allowed_bind_domains` is read by no bind or
requestToken path. Both look like security controls.

## Considered Options

* Document them as inert in `config/merovingian.conf.example`
* Remove the keys
* Leave them described as controls until enforcement lands

## Decision Outcome

Chosen option: "Document them as inert", because **a key that looks like a
security control and silently does nothing is worse than one that is absent** —
an operator who sets it believes they are protected.

### Negative Consequences

* The keys remain in the configuration surface, so an operator can still set
  something with no effect; only the documentation tells them so.
* This is explicitly a holding position. The recorded intent is either
  enforcement or removal, and leaving it documented indefinitely would be a
  slow way of choosing "leave them described as controls".

## Links

* [`docs/todos/capability-gaps.md`](../todos/capability-gaps.md), "Secure configuration"

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
