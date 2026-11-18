# A new push to a pull request cancels its superseded runs

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

Only `pages.yml` and `sonarcloud.yml` had a `concurrency` group. A fix pushed to a pull request left the run for the previous
head occupying runners until it finished, although nobody would read its result, and the new run queued behind it.

## Considered Options

* No `concurrency` group.
* One group per workflow and ref, cancelling except on `main` (as `pages.yml` does, and still does: see below).
* One group per workflow and pull request, used only by `pull_request` events, cancelling in progress; every other event gets
  a group of its own run.

## Decision Outcome

Chosen: the third. Each workflow that runs for a pull request has

```yaml
concurrency:
  group: <workflow file stem>-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || github.run_id }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

The prefix is a literal, not `github.workflow`: `packages.yml` is also called by `release.yml`, where `github.workflow` is the
caller's name. `tests/tooling/test_ci_tiers.py` enforces the shape.

Rejected:

* **No group.** Superseded runs keep runners the account has 20 of.
* **Per-ref groups.** GitHub keeps at most one pending run per group and cancels the older pending one when a third arrives,
  even with `cancel-in-progress: false`. On `main` that would cancel the checks, and the package publication, of a commit
  that merged.

## Consequences

* Only a run for a commit that is no longer the pull request's head is cancelled. ADR-0511's objection to `concurrency`
  (a cancelled required check shows as failed on the commit) applies only to that superseded commit, which nobody merges.
* `push`, `merge_group`, `schedule`, `workflow_dispatch` and `workflow_call` runs are never cancelled or held back, with one
  exception: `pages.yml` groups by `github.ref` and cancels only runs that are not on `main`, so it keeps its own group scheme
  and is not covered by "every non-pull-request run has its own group".

## Links

* Related [ADR-0511](0511-a-commit-runs-each-workflow-once.md)
