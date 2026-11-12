# The v1.0.0 tag moves to the release-workflow fix without a version bump

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

`v1.0.0` was pushed on 2026-11-12 at c354cc82, the 1.0.0 merge commit. Its `release.yml` run failed in
`linux-release-package` on `missing pkg-config module: libcurl`: the job's install step never had
`libcurl4-openssl-dev`, although `scripts/build-linux.sh` refuses to build without it. The jobs in `release.yml` run
only for a `v*` tag, and the last tag before this one was `v0.2.15-alpha`, from before libcurl was a dependency, so
nothing had exercised that list since. Staging, signing and publishing all wait for that job, so nothing was published
under `v1.0.0`.

Fixing `release.yml` is a packaging change. `docs/versioning.md` bumps `BUILD` for one, which would make the release
1.0.1. Which version ships, and how is this kind of gap kept from reaching a tag again?

## Considered Options

* Fix `release.yml` without a bump and move `v1.0.0` to the fix commit
* Fix `release.yml` as 1.0.1 and release `v1.0.1`, leaving `v1.0.0` unreleased

## Decision Outcome

Chosen option: "Fix `release.yml` without a bump and move `v1.0.0` to the fix commit", decided by the owner on
2026-11-12. The fix changes no source, build definition or package contents, only which packages the tag job installs.
Nothing had been published under `v1.0.0`, so no one holds an artifact that the moved tag would contradict.

This is an exception for this one fix. Every later branch follows the bump policy in `docs/versioning.md`, and a tag
from which anything was published is never moved.

`tests/tooling/test_release_workflow.py` now checks that `linux-release-package` and `freebsd-release-package` each
install a package for every `check_pkg_config_module` in `scripts/build-linux.sh` and `scripts/build-bsd.sh`. A
dependency added to a build script without its release package now fails `tests/tooling` on the pull request, not on
release day.

### Positive Consequences

* The first production release keeps the version its changelog, documentation and audit record already name.
* The tooling test runs on every pull request, so this gap is caught before a tag.

### Negative Consequences

* `v1.0.0` pointed at c354cc82 for a short time. A clone that fetched the tag then keeps the old target until it
  fetches with `--force`.
* The test maps each module to a package by hand. A new `check_pkg_config_module` fails the test until its package is
  added to that map, which is the intended prompt.

## Pros and Cons of the Options

### Fix `release.yml` as 1.0.1 and release `v1.0.1`

* Good, because it follows the bump policy and never moves a pushed tag.
* Bad, because 1.0.0 would exist as a tag that never released, while the changelog, README and audit record all name
  1.0.0 as the first production release.

## Links

* Relates to [ADR-0647](0647-versions-from-1-0-0-are-major-minor-build.md)
* Relates to [ADR-0648](0648-the-complement-blocker-is-waived-for-1-0-0-only.md)
