# Keep project phase out of the version string

* Status: superseded by [ADR-0647](0647-versions-from-1-0-0-are-major-minor-build.md)
* Date: 2026-09-06

## Context and Problem Statement

The project moves through phases — alpha, beta, production — and needs to
signal that. SemVer offers pre-release suffixes and build metadata for exactly
this.

## Considered Options

* A plain `0.MINOR.PATCH` string, with phase declared in `README.md` and
  `CHANGELOG.md`
* Encode phase in the version: pre-release suffix, build metadata, or epoch

## Decision Outcome

Chosen option: "A plain `0.MINOR.PATCH` string". There is no pre-release
suffix, no build metadata, no epoch. All three numbers are always present.
`MINOR` is a series marker, not a milestone, and a new series continues from
wherever the rollover happened rather than restarting at `.0`.

### Negative Consequences

* **A `MINOR` rollover must not be read as a phase transition.** Beta was
  declared mid-series at v0.10.59, and no `0.10.0` or `0.11.0` was ever cut.
  Anyone inferring phase from the version number will be wrong.
* Tooling that expects SemVer pre-release ordering gets no signal from the
  version alone.

### Positive Consequences

* One bump per branch, at merge time — not per commit — so the version is a
  branch identifier rather than a commit counter, and the intended version can
  be recorded in `CHANGELOG.md` when the branch opens.

## Links

* [`docs/versioning.md`](../versioning.md)

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
