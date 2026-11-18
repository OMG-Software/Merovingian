# `latest` is replaced only by a build of the same or a newer commit

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

Every push to `main` runs `packages.yml`, and its `publish-latest` job deletes the rolling `latest` release and creates it
again from the packages that run built. Nothing ordered two runs: when two pushes landed minutes apart, the run that
finished last won, so a slow build of the older commit could replace a newer `latest`. Its notes named the older commit,
and the tag, which `gh release create` put on `main`'s tip at that moment, named neither. `run_complement.py` and anyone
following "Release candidates" in `release-process.md` take that release as `main`'s current build. How should a publish
know whether it is newer than what is already there?

## Considered Options

* A concurrency group on the whole workflow, cancelling the older run.
* A concurrency group on `publish-latest` alone, plus a check, before anything is deleted, that the published release was
  built from an ancestor of this run's commit; the release's tag records that commit.
* Compare run numbers or creation times instead of commits.

## Decision Outcome

Chosen: the group on the job, plus the ancestry check. `publish-latest` is in the fixed group `packages-publish-latest`
with `cancel-in-progress: false`, so two publishes never interleave and one already deleting the old release finishes
creating the new one. `gh release create --target "${GITHUB_SHA}"` puts the `latest` tag on the commit the packages were
built from. Before deleting, the step reads that tag's commit and asks the compare API how this run's commit relates to
it: `ahead` or `identical` publishes; `behind` leaves the newer release and ends the job successfully, since nothing is
wrong; anything else (`diverged`, an empty answer, a failed call) fails the job without deleting anything.

Rejected:

* **A workflow-level group that cancels older runs.** It would cancel the package builds, which are the checks every push
  to `main` reports, and a tag's run (`release.yml` calls this workflow) would share the group. GitHub also does not
  promise that runs enter a group in push order, so the group alone cannot tell which run is newer.
* **Run numbers or times.** A re-run of an older run gets a later time, and run order is not commit order; only the
  commit graph says which build is newer.

## Consequences

* While a publish waits for the group, GitHub keeps one pending run and cancels any older one still waiting; that run's
  `publish-latest` shows as cancelled, and the newer run publishes.
* A force-push to `main` that rewrites the published commit makes every later publish fail until a maintainer deletes
  `latest` (`gh release delete latest --cleanup-tag`) and re-runs the newest run's `publish-latest`.
* The first publish after this change compares against a tag that `gh release create` put on `main`'s tip at the time,
  which may be newer than what that release was built from. A run older than that tip leaves `latest` until the next push.
* A tag's run skips `publish-latest` (its `if` requires a push to `main`), so it never waits for or touches `latest`.

## Links

* Related [ADR-0742](0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)
