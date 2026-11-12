# Analyses, then build and test jobs, then packages take runners

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

## Context and Problem Statement

[ADR-0580](0580-the-long-ci-jobs-wait-for-a-gate-so-sonar-and-codeql-take-runners-first.md) put
every job of `ci.yml` and `packages.yml` behind an instant gate, so Sonar and CodeQL join the
runner queue first. The build and test jobs and the package jobs then joined together, and two
build and test workflows (`postgres-integration.yml`, `reproducible-build.yml`) had no gate and
joined with the analyses. The owner's order is: Sonar, CodeQL, CodeRabbit, tsan, asan and the other
analyses, then the build and test jobs, then the package and release jobs. GitHub has no job
priority and does not serve its queue in arrival order, so the only lever is when a job joins it.

## Decision Drivers

* Each tier should be able to take runners before the next one asks for them.
* No required check may be renamed, and a failed gate must never let a required check pass unrun.
* The analyses that need nothing must still fit the 20-runner cap together.

## Considered Options

* Three tiers: analyses need nothing; build and test jobs wait for an instant gate; package jobs
  wait for a gate that sleeps first.
* `workflow_run` triggers that start packaging after the build and test workflow finishes.
* Delays inside the analysis tier, to order Sonar, CodeQL, tsan and asan among themselves.

## Decision Outcome

Chosen option: three tiers. The analyses (`sonarcloud`, CodeQL, `tsan`, `asan-ubsan`, coverage,
fuzzing, clang-tidy, gitleaks, dependency review and triage, the docs build) need nothing and join
the queue when the pull request is pushed. Every build and test job (`ci.yml`, and now
`postgres-integration.yml` and `reproducible-build.yml`) that needs nothing else needs its
workflow's `queue-after-analyses`, which runs `true`. Every package job needs `packages.yml`'s gate,
renamed `queue-after-build-and-test` ("Queue after the build and test jobs"), which runs
`sleep 60`, so the package jobs join after the build and test jobs. Each gated job keeps
`if: ${{ !cancelled() }}` for ADR-0580's reason. Neither gate is a required check.

`workflow_run` was rejected: it runs in the default branch's context, reports its checks against
no pull request head, and would turn the required package checks into ones a pull request never
gets. Delays inside the analysis tier were rejected: the tier fits the cap (15 jobs start at once
with the gates), so every analysis takes a runner as soon as one is free; a delay would only make
CodeQL or the sanitizers finish later. CodeRabbit runs on its own service, not on these runners,
so nothing here orders it.

`tests/tooling/test_ci_runner_order.py` names each gated workflow's gate, requires the build and
test gates to run `true` and the package gate to `sleep` at least 30 seconds, requires Sonar,
CodeQL, tsan and asan to need nothing, and still caps the jobs that start at once at 20.

### Negative Consequences

* A sleep is a heuristic: when other pull requests hold every runner, GitHub may still start a
  package job before a build and test job that joined earlier.
* The package gate holds a runner for a minute on every pull request and tag.
