# A policy rule change commits with its admin action and audit row

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C49.

## Context and Problem Statement

ADR-0629 made an administrator's account action and its audit row one transaction. The trust-and-safety actions were left
as they were: the policy-rule upsert and delete committed the rule, then an `admin_actions` row, then a best-effort audit
row whose result was discarded, and the review action wrote the audit row first and the rule after it. A storage failure
between the steps left a rule in force with no audit row, or an audit row accusing a rule that was never stored.

## Considered Options

* `commit_policy_rule_with_audit` and `commit_policy_rule_removal_with_audit`: the rule statement, the `admin_actions`
  insert and the audit insert in one `commit_persistent_transaction`; the in-memory rule, action and audit window follow
  only a successful commit; callers then call `remember_local_audit`. The review route uses the same function.
* Keep the three writes separate and make the audit insert's failure return 500 (the rule already in force).
* Audit first, rule second.

## Decision Outcome

Chosen option: one transaction, as ADR-0629. The first alternative leaves a rule in force that nobody can attribute, the
second accuses an administrator of a change that did not happen; both are the reasons ADR-0629 rejected them for account
actions. The durable audit row is built by `local_audit_row` (moved out of `AuthService.cpp` so the three writers share it),
which bounds and sanitises it exactly as `append_local_audit` does. `DELETE` of a rule that does not exist is still 404,
decided before the transaction; a failed commit is 500.

Not changed: room alias deletion and directory visibility by a server administrator write no administrator audit row; they
are room actions a room moderator can also take and the finding did not assess them as administrator actions.

## Links

* Follows [ADR-0629](0629-an-administrators-state-change-and-its-audit-row-commit-in-one-transaction.md)
