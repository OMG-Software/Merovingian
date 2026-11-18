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
built from. The step first asks the compare API whether `main` still holds this run's own commit, and fails if it does
not: a run of a discarded history never publishes, whatever `latest` holds. Before deleting, it reads the tag's commit
and asks how this run's commit relates to it: `ahead` or `identical` publishes; `behind` leaves the newer release and
ends the job successfully, but only while `main` still holds the published commit and that commit has its release, and
fails once a reset of `main` has removed it or when the tag is left without a release (nothing would ever publish
again); anything else (`diverged`, an empty answer, a failed call) fails the job without deleting anything. The tag is
looked up on its own, not through the release: `gh release create` reuses an existing tag whatever `--target` says, so a
tag left behind by a deleted release is compared like any other. The tag is the watermark of what is published and is
never deleted: the step deletes the old release, keeping its tag, then moves the tag to this run's commit with the git
refs API (or makes it, on a first publish), then creates the release on it with `--verify-tag`. Deleting the tag with
the release instead would let a failed creation erase it: an older queued run would then find neither and publish as if
`latest` had never existed, moving it backwards. With the tag kept, that run stops at the `behind` path, which fails a
tag that has no release. A release whose tag is gone fails the job, as does any answer about the release other than
"found" or a 404.

Rejected:

* **A workflow-level group that cancels older runs.** It would cancel the package builds, which are the checks every push
  to `main` reports, and a tag's run (`release.yml` calls this workflow) would share the group. GitHub also does not
  promise that runs enter a group in push order, so the group alone cannot tell which run is newer.
* **`queue: max` on the job's group.** It would keep a newer commit's publish waiting instead of cancelled, but GitHub
  documents it only for a workflow-level group; see Consequences.
* **Run numbers or times.** A re-run of an older run gets a later time, and run order is not commit order; only the
  commit graph says which build is newer.

## Consequences

* With the default `queue: single`, a group holds at most one pending job: one that arrives while another waits cancels
  the waiting one, and GitHub does not promise that jobs arrive in push order. A slow build of an older commit can
  therefore cancel a newer commit's waiting publish and then publish itself. `latest` never goes backwards (the older
  build is still newer than what it replaces), but it can lag behind `main` until the next push, or until a maintainer
  re-runs the cancelled `publish-latest`, which then sees itself `ahead` and publishes. GitHub's `queue: max` keeps up
  to 100 pending entries instead, which would remove the lag; it is not used because GitHub documents it only on a
  workflow-level group, and an unsupported key on this job-level group would fail `packages.yml` on every push to
  `main`. The ancestry check keeps either setting safe, so adopting it needs only a run that shows the job accepts it.
* A force-push to `main` that rewrites the published commit, or a reset of `main` behind it, makes every later publish
  fail until a maintainer recovers: wait for any `publish-latest` in progress, delete `latest` (with
  `gh release delete latest --cleanup-tag` when the release exists, or the tag's ref alone when only the tag is left),
  then re-run the newest run's `publish-latest`. A run of the old history fails at the check of its own commit, so it
  cannot publish after the deletion; only one already past its checks can, which is why the recovery waits for it.
* The first publish after this change compares against a tag that `gh release create` put on `main`'s tip at the time,
  which may be newer than what that release was built from. A run older than that tip leaves `latest` until the next push.
* A tag's run skips `publish-latest` (its `if` requires a push to `main`), so it never waits for or touches `latest`.

## Links

* Related [ADR-0742](0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)
