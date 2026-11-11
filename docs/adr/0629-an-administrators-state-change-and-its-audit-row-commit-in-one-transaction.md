# An administrator's state change and its audit row commit in one transaction

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-logging-privacy.admin-moderation.audit-write-not-atomic`.

## Context and Problem Statement

`set_local_user_moderation` and `deactivate_user_account` wrote the account state in one transaction and the `audit_log`
row in another, with the append's result discarded. Deactivation could also return 500 after the irreversible flag was
durable and before the audit call. A completed administrative action could leave no durable row.

## Considered Options

* Commit the state change and its audit row in one transaction (`commit_user_account_state_with_audit`,
  `commit_user_deactivation_with_audit`), as `commit_local_media_moderation` does. A failed audit write fails the action.
* Write the audit row first, then the state.
* Keep two writes and log a failed audit append loudly.

## Decision Outcome

Chosen option: the first. The audit row exists if and only if the change does.

Audit-first leaves a row for an action that did not happen, which is worse than a missing row because it accuses.
Logging leaves the gap and relies on someone reading a log. The cost of the first option is that a store that cannot
insert audit rows refuses administrative account actions with 500. That is the intended failure: an action nobody can
later attribute should not be taken.

Deactivation commits the `deactivated` flag with its `auth.account_deactivated` row, and only when the flag is being set:
the repeat that completes a half-finished deactivation adds no second row. Revocation follows and may still fail with 500;
the row already says the account was closed. A row the audit rate gate suppresses is not written, as before, and the state
change then uses the plain writer.
