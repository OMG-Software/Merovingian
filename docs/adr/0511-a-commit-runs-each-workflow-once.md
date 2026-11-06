# A commit runs each workflow once

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

`sanitizers` and `static-analysis` had a bare `on: push` as well as `on: pull_request`, so one push to a pull request's branch
ran each twice: about 38 and 19 minutes for one commit on #560. `packages` did the same for `feature/**` branches.
`postgres-integration` compiled and ran the whole suite, 33 minutes on #560, before a separate step ran the PostgreSQL scenarios
in 22 seconds. Only the integration binary reads `MEROVINGIAN_TEST_POSTGRESQL_URI`, and that suite already runs on Ubuntu with
the same compiler. What can CI stop running without losing a check on `main` or on a pull request?

## Considered Options

* Drop `pull_request` from the workflows and rely on `push`.
* Keep both events, and cancel one with a `concurrency` group.
* Limit `push` to the branches `ci.yml` lists.
* Keep the whole suite in `postgres-integration` for the extra configuration.
* Build the integration binary and run one tag.

## Decision Outcome

Chosen: limit `push` to `main`, `master`, `claude/**` and `codex/**`, and run `[postgresql]` from an integration binary built
on its own. `tests/tooling/test_ci_run_scope.py` fails on a workflow that runs on both events for an ordinary pull request's
branch, and on a scenario that uses PostgreSQL without the tag.

The job filters on `[postgresql]` alone, not on the old `[database][postgresql][integration]`. Catch2 requires every tag in a
filter, and scenarios without all three ran here only because the whole suite ran first with the URI set. Narrowing the job
with the old filter would have dropped them silently.

Rejected:

* **Dropping `pull_request`.** A pull request from a fork gets no `push` run in this repository, so its required checks would
  never report.
* **A `concurrency` group.** It cancels one of the two runs, and a cancelled run of a required check shows as a failure on the
  commit. It also still starts both.
* **Keeping the whole suite in `postgres-integration`.** The URI changes nothing for the unit and conformance binaries, which
  never read it, nor for an integration scenario that does not use it. The rest of the job repeated `ubuntu-build-and-test`.

The documentation site keeps both events. It builds strictly on every branch by design, so a branch with no pull request is
still checked, and the duplicate takes under a minute.

## Consequences

* A push to a branch with no pull request no longer runs the sanitizers, `clang-tidy` or the packages. Opening a pull request,
  or a draft, runs them.
* `claude/**` and `codex/**` still run both events if a pull request is opened from one. They are listed because an automated
  agent may push there and open no pull request.
* A scenario that reaches PostgreSQL must carry `[postgresql]`. Without the URI these scenarios skip, so an untagged one passes
  in CI having tested nothing. `coverage` and `sonarcloud` still run the whole suite with the URI set, so its PostgreSQL code stays
  measured.
