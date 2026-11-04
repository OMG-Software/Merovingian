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

* Remove `continue-on-error` from every BSD job (chosen)
* Keep it on the NetBSD package pair and leave the retry as it was
* Replace the pair with a gate job that passes when either attempt passes, as `rpm-all-images` does

## Decision Outcome

Chosen option: remove it, because the owner decided that every BSD job must be required, and a
mask on any one of them is how a platform regresses unseen.

The retry therefore cannot turn a red `NetBSD package` green: GitHub marks the run red if any job
failed. `netbsd-pkg-retry` now runs on `always() && needs.netbsd-pkg.result == 'failure'`, so it
still shows whether a second build passes, and re-running the failed job is what clears the check.
The `!failure()` guard on signing and publishing sees the failed `netbsd-pkg` and does not publish.
The staging step downloads the NetBSD package without `continue-on-error`, so a missing artifact
stops staging instead of publishing a release without it.

A gate job would keep the retry's rescue, but the attempt jobs would then need the mask this
decision removes, and the check names the repository ruleset requires would have to move. Do not
re-add `continue-on-error` to a BSD job to make a flaky run green; fix or re-run the job.

NetBSD stays refused at startup and its thumbnail decoder stays refusing (ADR-0378, ADR-0419);
the NetBSD suite already asserts those outcomes, so this decision weakens neither.

### Consequences

* A failing OpenBSD or NetBSD suite or package blocks the merge, and a failing NetBSD package
  blocks publishing `latest`.
* A QEMU flake on NetBSD now needs a manual re-run of the failed job.
* Job names are unchanged, so the ruleset's exact check names still match.
