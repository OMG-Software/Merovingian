# A pull request runs a core gate, and the merge queue runs the full matrix

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

A push to a pull request started 76 jobs: about 32 runner-hours on an account limited to 20 hosted runners. The jobs spent
7,533 minutes waiting for a runner and 1,936 running, and the slowest workflow took 7 h 40 min to report. Every pull request
push built and tested ten Linux distributions, three BSDs and every package format, even though most pushes to a pull request
are iterations that only need to know whether the change works. How can a pull request get a fast answer without letting a
change reach `main` unchecked on any platform?

## Decision Drivers

* Nothing may reach `main` without every platform and package job passing, as before.
* Every check the "Protect main" ruleset requires must report on a pull request, or the pull request can never merge.
* A pull request push should start few enough jobs to fit the 20-runner cap.

## Considered Options

* Keep running everything on every pull request push.
* Run the full matrix only on `main` and on a schedule.
* Run the full matrix when a `full-ci` label is added to a pull request.
* Run a core gate on the pull request and the full matrix in GitHub's merge queue (`merge_group`).

## Decision Outcome

Chosen: a core gate on the pull request and the full matrix in the merge queue.

On `pull_request`, `ci.yml` runs `ubuntu-build-and-test` and `freebsd-build-and-test` (and the gate they wait for), and the
analysis workflows (sanitizers, `clang-tidy`, CodeQL, PostgreSQL, fuzz, coverage with the Sonar scan, secret scan, dependency
triage, docs) run as before. `dependency-review` and the SonarQube Cloud scan run only for a pull request from this repository
(the scan also on a push to `main`). Every other `ci.yml` job and every `packages.yml` job has `github.event_name != 'pull_request'`
in its job-level `if:`, so on a pull request it is skipped. A job skipped by its `if:` reports success, so its required check
passes on the pull request. Every workflow that runs for a pull request also runs for `merge_group`, where no `ci.yml` or
`packages.yml` job is skipped for being a pull request. Two things still run only on a pull request or on `main`:
`dependency-review`, and the SonarQube Cloud scan, which is skipped for `merge_group` and `workflow_dispatch`. The pull
request's scan already analysed its merge with main, a scan of a `gh-readonly-queue` branch would only add a throwaway
SonarQube Cloud branch, and the Sonar result is not a required check. The merge queue merges only a commit on which every
required check passed. `reproducible-build.yml` moves from a path-filtered
`pull_request` trigger to `merge_group`.

`packages.yml` keeps its `pull_request` trigger although all its jobs skip there: a workflow that never starts leaves its
required checks waiting forever, and the pull request could never merge. `tests/tooling/test_ci_tiers.py` lists the
ruleset's required checks and fails if one stops reporting for either event; keep that list and the ruleset in step.

The merge queue must be turned on in the "Protect main" ruleset. Until the owner does, a pull request can merge after the
core gate alone, and the full matrix first runs on the push to `main`.

The ruleset gates the queue only on its required checks. `ubuntu-26.10-build-and-test` and `NetBSD package` are not required
([ADR-0502](0502-every-bsd-job-is-required-and-the-netbsd-retry-cannot-rescue-it.md) for NetBSD), so their failure in the
queue does not block a merge; it blocks staging, signing and publishing `latest`. Adding them to the ruleset is the owner's
decision.

Rejected:

* **Everything on every push.** It is what made a pull request wait hours for a runner.
* **`main` and a schedule only.** A change that breaks one platform is found after it is on `main`.
* **A `full-ci` label.** A pull request merged without the label skips the full matrix, so the guarantee depends on someone
  remembering.

## Consequences

* A pull request's red or green answer now comes from about 15 jobs instead of 51.
* A merge waits for the full matrix in the queue. Each queue entry runs it once, on the commit that becomes `main`.
* A required check skipped on a pull request shows as passed there; its real result is the merge queue's.

## Links

* Refines [ADR-0743](0743-analyses-then-build-and-test-then-packages-take-runners.md)
* Related [ADR-0841](0841-agent-branches-run-ci-through-a-pull-request-or-by-hand.md)
