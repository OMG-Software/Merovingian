# One coverage build feeds the Sonar scan, and Codecov uploads from its own job

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

`coverage.yml` (about 50 minutes) and `sonarcloud.yml` (about 62) each built the project with GCC 14 and `--coverage`, ran
every suite against a live PostgreSQL and ran gcovr with the same options: one for Codecov, one for the SonarQube Cloud scan.
[ADR-0250](0250-sonarqube-cloud-analysis-runs-in-ci-against-the-build-s-compilation-database.md) kept them apart so the
Codecov action, which skips its CLI's signature check, never ran beside `SONAR_TOKEN`. Can one build serve both without
weakening that?

## Considered Options

* Keep two workflows that each build and test.
* One job: build, test, both gcovr reports, the Sonar scan, then the Codecov upload, with the token only in the scan step.
* One job that builds, tests, writes both reports and scans; a second job in the same workflow downloads the Cobertura report
  and uploads it to Codecov.

## Decision Outcome

Chosen: the third. `coverage.yml` has a `coverage` job (the name the ruleset requires) that builds once, runs the suites, writes
`coverage.xml`, the HTML report and `sonarqube.xml` in one gcovr run, uploads them as an artifact and runs the scan. The scan
step is skipped for a pull request from a fork, which gets no secrets; everything else in the job still runs for it. A `codecov`
job `needs: coverage`, downloads the artifact and uploads it. `sonarcloud.yml` is deleted.
`tests/tooling/test_coverage_workflow.py` fails if `SONAR_TOKEN` and the Codecov action end up in the same job.

Rejected:

* **Two builds.** About 45 runner-minutes spent twice on every push for the same counters.
* **One job, ordered steps.** A step can read every secret its job uses from the runner worker's memory, which is how the
  tj-actions compromise took secrets it was never passed. Putting the scan before the upload does not keep the token from the
  Codecov CLI. ADR-0250's other objection, that handing a build to another workflow needs `workflow_run` and an artifact as
  large as the build, does not apply here: the second job is in the same workflow and needs only the Cobertura XML.

## Consequences

* The `coverage` check now also fails when the Sonar scan fails.
* A failed Codecov upload no longer blocks a merge. Before, the upload ran inside `coverage` with `fail_ci_if_error: true`,
  so a Codecov outage failed the required check; now it fails only the `codecov` job, which the ruleset does not require.
  The coverage counters still gate through the Sonar quality gate, and an outage of a third-party upload service should not
  hold every merge. To make an upload failure block again, the owner adds `codecov` to the required checks; the workflow
  needs no change.
* The artifact is kept for 30 days, as long as GitHub lets a maintainer re-run only the `codecov` job, so a retried upload
  finds its report instead of needing a new instrumented build.
* Codecov receives a report for pull requests of any base and for the merge queue, as Sonar's workflow ran; before, Codecov saw
  pull requests to `main` only.
* ADR-0250's choice of a separate Sonar build is superseded; its use of the compilation database and of GCC stands.

## Links

* Supersedes in part [ADR-0250](0250-sonarqube-cloud-analysis-runs-in-ci-against-the-build-s-compilation-database.md)
* Related [ADR-0843](0843-ci-wraps-the-compiler-in-ccache-and-only-main-writes-the-cache.md)
