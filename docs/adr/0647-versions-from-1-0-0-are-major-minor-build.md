# Versions from 1.0.0 are MAJOR.MINOR.BUILD

* Status: accepted
* Date: 2026-11-11

## Context and Problem Statement

Before 1.0.0 the version was `0.MINOR.PATCH` ([ADR-0047](0047-keep-project-phase-out-of-the-version-string.md)).
`MINOR` was a rolling series marker with no `.0` start, and `PATCH` was bumped once per branch. 1.0.0 is cut, so the
project needs a scheme for the releases after it. What do the three numbers mean from 1.0.0?

## Considered Options

* `MAJOR.MINOR.BUILD`: `BUILD` is bumped once per branch, exactly as `PATCH` was; `MINOR` and `MAJOR` change when the
  owner decides
* Keep `MINOR` as a rolling series marker after 1.0.0, as in `0.MINOR.PATCH`

## Decision Outcome

Chosen option: "`MAJOR.MINOR.BUILD`".

* `BUILD` is incremented once per branch, with the same bump policy, the same locations and the same exemption for
  documentation-only changes as `PATCH` had.
* `MINOR` and `MAJOR` change only when the owner decides. The decision states the version that follows. The owner has not
  said when either changes, and this record does not say.
* Project phase stays out of the version string. That part of ADR-0047 still holds and is restated here, because
  ADR-0047 is superseded.
* The 0.x rules are history. `docs/versioning.md` keeps a short note of them.

### Negative Consequences

* Nothing in the scheme says when `MINOR` or `MAJOR` change. Until the owner decides, a reader cannot infer that from the
  number.

## Pros and Cons of the Options

### Keep `MINOR` as a rolling series marker

* Good, because it is the smallest change.
* Bad, because a `MINOR` that is a rollover marker with no `.0` start carries no meaning once the version is 1.0.0 or
  later, and the upgrade fixture rules in `docs/release-process.md` name minor series starts such as 1.1.

## Links

* Supersedes [ADR-0047](0047-keep-project-phase-out-of-the-version-string.md)
* [docs/versioning.md](../versioning.md)
