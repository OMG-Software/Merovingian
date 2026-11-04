# Every BSD job is required, and the NetBSD retry cannot rescue its first build

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-04

## Context and Problem Statement

`openbsd-build-and-test`, `netbsd-build-and-test`, `NetBSD package` and `NetBSD package (retry)`
carried a job-level `continue-on-error: true`. A job with it reports `success` to the rest of the
workflow whatever its steps did, so a red OpenBSD or NetBSD suite never blocked a merge, and a
failed NetBSD package never blocked publication. `docs/platform-support.md` already says a
regression on a Tier 1 platform blocks merge; the workflow did not do that.

The NetBSD package retry relied on the mask. `netbsd-pkg` exposed a `build_succeeded` output
because `.result` read `success` even after a failure, and `netbsd-pkg-retry` ran on that output
and was itself masked, so one flaky QEMU boot could be rescued into a green run.

## Considered Options

* Remove `continue-on-error` from every BSD job and delete the retry job (chosen)
* Remove it, but keep the retry job, running on a real `netbsd-pkg` failure
* Keep it on the NetBSD package pair and leave the retry as it was
* Replace the pair with a gate job that passes when either attempt passes, as `rpm-all-images` does

## Decision Outcome

Chosen option: remove it and delete `netbsd-pkg-retry`, because the owner decided that every BSD
job must be required, and a mask on any one of them is how a platform regresses unseen.

Once the mask is gone the retry cannot change a run's result: GitHub marks the run red if any job
failed, and the `!failure()` guard on signing and publishing sees the failed `netbsd-pkg` whatever
the retry did. A kept retry would spend a second VM build to report what "re-run failed jobs"
reports. The repository ruleset (`Protect main`) names neither `NetBSD package` nor
`NetBSD package (retry)`, so deleting the job leaves no required check without a reporter.

The staging step downloads the NetBSD package without `continue-on-error`, so a missing artifact
stops staging instead of publishing a release without it.

A gate job would keep the retry's rescue, but the attempt jobs would then need the mask this
decision removes. Do not re-add `continue-on-error` to a BSD job to make a flaky run green; fix or
re-run the job.

NetBSD stays refused at startup and its thumbnail decoder stays refusing (ADR-0378, ADR-0419);
the NetBSD suite already asserts those outcomes, so this decision weakens neither.

### Consequences

* A failing OpenBSD or NetBSD suite blocks the merge: the ruleset requires `openbsd-build-and-test`
  and `netbsd-build-and-test`, as it does `OpenBSD package`.
* A failing `NetBSD package` blocks publishing `latest` but is not in the ruleset, so it does not
  block a merge. Adding it is the repository owner's change to make.
* A QEMU flake on a NetBSD job now needs a manual re-run of the failed job.
* Job names are unchanged, so the ruleset's exact check names still match.
