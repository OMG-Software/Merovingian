# Agent branches run CI through a pull request or by hand

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

[ADR-0511](0511-a-commit-runs-each-workflow-once.md) limited `push` to `main`, `master`, `claude/**` and `codex/**`, keeping
the two agent prefixes because an agent might push there and open no pull request. In practice agents open pull requests from
those branches, so each of their commits ran every workflow twice: once for `push` and once for `pull_request`. On one commit
that was 731 of 1,936 runner-minutes, 38 %, on an account with 20 runners.

## Considered Options

* Keep `claude/**` and `codex/**` in `push`.
* Keep them, and cancel the duplicate with a `concurrency` group keyed on the commit.
* Drop them from `push`, and add `workflow_dispatch` so a branch with no pull request can be run by hand.

## Decision Outcome

Chosen: drop them, and add `workflow_dispatch`. `push` now lists only `main`, `master` and, for `packages.yml`,
`alpha-release`. `tests/tooling/test_ci_run_scope.py` fails on a `push` trigger that lists an agent prefix.

Rejected:

* **Keeping them.** Every agent commit with a pull request pays for every workflow twice.
* **A commit-keyed `concurrency` group.** ADR-0511 already rejected this. A cancelled run of a required check shows as a failure
  on the commit, and which of the two runs survives depends on which event arrives last.

## Consequences

* A push to an agent branch with no pull request runs only the documentation site. Open a pull request, or a draft, or start the
  workflows from the Actions tab.
* ADR-0511's `push` branch list is superseded; its PostgreSQL decision stands.

## Links

* Supersedes in part [ADR-0511](0511-a-commit-runs-each-workflow-once.md)
