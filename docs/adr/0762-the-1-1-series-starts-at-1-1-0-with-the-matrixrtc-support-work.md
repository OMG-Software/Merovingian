# The 1.1 series starts at 1.1.0 with the MatrixRTC support work

* Status: accepted
* Date: 2026-11-16

## Context and Problem Statement

[versioning.md](../versioning.md) says `BUILD` is the working counter and that `MINOR` changes "only when the owner
decides". The branch that adds MatrixRTC support is a run of slices that add features and, later, the first schema
migration since 1.0.0. Its first slice is `use_state_after` on `GET /sync`. Which version does that work carry?

## Considered Options

* Continue with `BUILD` bumps from 1.0.3 (1.0.4 onward) (rejected)
* Stay on 1.0.x until the first schema migration lands (rejected)
* Start the 1.1 series at 1.1.0 with this work

## Decision Outcome

Chosen option: start the 1.1 series at 1.1.0. The owner decided this on 2026-11-16, and this branch, whose first slice
is `use_state_after`, carries 1.1.0.

A 1.0.x number means a fix or a small change to the 1.0 server. This work adds new client-visible features and will add a
schema migration, which an operator upgrading from 1.0.x must be able to see in the version before reading a change log.
Bumping `BUILD` would hide that, and waiting for the migration would number the early slices as fixes and move the
series start to a commit that is not the first of the series.

### Consequences

* The upgrade fixture that [tests/fixtures/upgrade/README.md](../../tests/fixtures/upgrade/README.md) ties to the start of
  the 1.1 series is generated from `main` commit `5f458d57` (1.0.3) in a later commit on this branch, not by this slice.
* Every location in the [versioning table](../versioning.md#every-location-that-must-be-updated) moves to 1.1.0 together.
