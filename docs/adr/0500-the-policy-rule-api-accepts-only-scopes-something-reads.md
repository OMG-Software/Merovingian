# The policy rule API accepts only scopes something reads

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`PUT /_matrix/client/v3/admin/safety/policy_rules/{scope}/{entity}` stored a rule under any scope. `find_policy_rule`
(`runtime.cpp`) is called with exactly four scopes: `registration` (`auth_service.cpp`), `federation`
(inbound requests), `media` (`media_service.cpp`) and `room` (`room_service.cpp`). A rule in `invite`, `user`,
`account` or a typo was stored, listed and audited as if in force, and never consulted. The admin review route writes
only `federation`, `media` and `room`, all read.

## Considered Options

* Accept any scope, as before.
* Refuse a scope nothing reads with `400 M_INVALID_PARAM`, before storing.
* Wire up invite and account scopes.

## Decision Outcome

Chosen option: refuse. A rule that looks enforced and is not is the same fault as an inert configuration key
([ADR-0498](0498-a-documented-configuration-key-is-enforced-or-removed-and-redaction-keys-only-accept-true.md)).
Wiring invite or account rules is a feature with its own design (account lock and suspension are already enforced from
account state, not rules). `PolicySurface::invite`, its only user `evaluate_invite_policy`, and
`account_enforcement_statements` are removed. A future scope must be added to `is_enforced_policy_rule_scope` in the
same change that makes something read it. DELETE is not restricted, so a rule stored under an old scope can still be
removed.
