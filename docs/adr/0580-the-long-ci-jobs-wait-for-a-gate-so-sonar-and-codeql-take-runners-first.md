# The long CI jobs wait for a gate, so Sonar and CodeQL take runners first

* Status: accepted (extended by [ADR-0743](0743-analyses-then-build-and-test-then-packages-take-runners.md): package jobs wait behind a later gate)
* Deciders: James Chapman
* Date: 2026-11-07

## Context and Problem Statement

GitHub Actions has no job priority. When a pull request is pushed, every workflow it triggers creates its jobs in the same
second, and every job without `needs:` joins one queue for runners. The organisation runs at most 20 jobs at once, across
every pull request, so the rest wait. The queue is not served in the order jobs joined it. On #567's first run, while #566's
CI held every runner, CodeQL waited from 15:14:09 to 15:31:47, and three jobs that joined at 15:18 and 15:27 got runners
before it. A queued job's place cannot be relied on, so the only way to start a job at once is for no job to be waiting.

On #566 at `d567ec02`, 34 jobs needed nothing and joined at once. `sonarcloud` joined last, 5 seconds after the others,
because its workflow's `concurrency` group first cancels the previous run. It was still queued minutes later, behind the OS
builds of `ci.yml` and the package builds of `packages.yml`. `sonarcloud` takes about an hour (an instrumented build and every
suite, then the scan), and CodeQL is the next longest. Every minute either waits in the queue adds a minute before a pull
request can turn green. How can the analyses start first when GitHub offers no ordering?

## Decision Drivers

* Sonar and CodeQL should get a runner as soon as the pull request is pushed.
* No required check may be renamed: the `main` ruleset matches checks by exact name.
* A failure of the ordering mechanism must never make a required check pass without running.
* Feedback from the quick jobs should not be delayed.

## Considered Options

* A short gate job in `ci.yml` and `packages.yml` that every job there with no other dependency `needs:`.
* Trigger the long workflows with `workflow_run` once the analyses have started.
* Merge every workflow into one, so that one `needs:` graph orders everything.
* Hold the quick jobs back instead, so the analyses go before them.
* A paid plan with a higher job cap.

## Decision Outcome

Chosen option: the gate. `queue-after-analyses` (check name "Queue after Sonar and CodeQL") checks nothing out, holds no
permissions and runs `true`. Every job in `ci.yml` and `packages.yml` that needed nothing now needs it, and so joins the
queue only after it has finished. The jobs that already needed another job (the two Fedora aggregates, the Complement image,
and the staging, signing and publishing chain) are unchanged. A pull request now starts 15 jobs at once, under the cap, so
when the runners are free `sonarcloud` and CodeQL do not queue. The OS and package jobs queue a few seconds later and take
runners as they free up.
`tests/tooling/test_ci_runner_order.py` counts the jobs that need nothing in every workflow that runs for a pull request
(one per matrix entry) and fails when they exceed 20. It also fails when a job in the two workflows needs nothing, or when
an analysis needs anything.

Every job that waits for the gate has `if: ${{ !cancelled() }}`. A job skipped because a job it needs failed reports a
skipped check, and GitHub counts a skipped required check as passed. Without the condition, an infrastructure failure of
the gate would let a pull request merge with no OS build or package having run. With `!cancelled()` the job still waits for
the gate, runs whether the gate passed or failed, and stops when the run is cancelled. `always()` was rejected: it would
also run the jobs of a cancelled run, so cancelling the CI of a superseded push would no longer stop its queued jobs.

The gate is also an ancestor of every job further down, and two of GitHub's status checks look at every ancestor, not only
at a job's own `needs`. `success()`, which GitHub applies to a job with no `if`, is false once any ancestor failed, and
`failure()` is true. So a job that waits for the gate through another job states its condition on what it needs by name
(`needs.<job>.result`, with `!cancelled()` or `always()`) and never uses `success()` or `failure()`, written or implicit.
Otherwise a failed gate would skip `complement-image` (its skipped check would count as passed), and signing and
publishing the rolling release, although every package built. `complement-image` therefore runs when `debian-pkg`
succeeded. `sign-package-assets` needs the nine package jobs as well as staging, and runs when staging succeeded and
none of them failed or was cancelled. `publish-latest` runs when signing succeeded. Each keeps what it required before
the gate existed, with the gate left out.

`sonarcloud` keeps its `concurrency` group. With 15 jobs starting, the 5 seconds it spends cancelling the previous run no
longer cost it a runner, and the group still stops two analyses of one pull request from running at the same time.

Rejected:

* **`workflow_run`.** It runs the copy of the workflow on the default branch, not the pull request's, and its runs do not
  report as the pull request's checks, so the required OS and package checks would never report.
* **One workflow.** It would rewrite every workflow, mix their permissions and triggers, and give the same order the gate
  gives.
* **Holding back the quick jobs.** `gitleaks`, `dependency-review` and the documentation build finish within a minute and
  free their runner, so holding them back barely helps Sonar while it delays the cheapest feedback. What kept Sonar waiting
  was the 21 OS and package jobs that each hold a runner for 7 to 15 minutes.
* **A higher job cap.** It costs money. The gate removes the wait at no cost while the jobs that start at once stay under 20.

### Negative Consequences

* The gate orders one push, not the organisation. The 20 runners are shared by every pull request, so while another pull
  request's CI holds them, this one's analyses queue with everything else, in an order GitHub does not keep. Nothing in a
  workflow can change that: only free runners, or a higher cap, can.
* The OS and package jobs start a few seconds later than before, after the gate has run. On a push where runners are free,
  that is the whole cost.
* A new job in `ci.yml` or `packages.yml` must need the gate or another job. One that needs the gate directly carries
  `if: ${{ !cancelled() }}`. One that needs another job does not: `!cancelled()` alone would run it after what it needs
  had failed. It states its condition on its own needs, as above, never with `success()` or `failure()`. The tooling
  test fails when such a job has no `if`, uses `success()` or `failure()`, or uses `!cancelled()` without a
  `needs.<job>.result` check. It accepts `always()`, which runs a job whatever its needs did, because the test cannot
  read steps. The Fedora and RPM aggregates fail in a step unless their legs succeeded. Staging fails on a missing
  artifact, and signing checks every package job's result by name, because a package can fail after uploading. A new
  job on `always()` must judge its needs the same way. A new workflow that runs for pull requests adds to the jobs that start at once; past 20, it needs a
  gate of its own.
* The cap of 20 is the plan's. If the plan changes, update `RUNNER_CAP` in the tooling test.

## Links

* Refines [ADR-0511](0511-a-commit-runs-each-workflow-once.md), which cut the number of runs per commit
