# Documentation-only changes do not require a version bump

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The versioning guide required a patch increment for every branch, including
documentation-only work. This caused a coding-rules rewrite to change version
strings in the build, executables, and package metadata. The project owner
clarified that a documentation-only change does not require a version bump.

## Considered Options

* Require a version bump for every branch.
* Exempt documentation-only changes from the required bump.

## Decision Outcome

Chosen option: exempt documentation-only changes. Keep the current version and
record the documentation changes in its changelog section. Coding guidance and
`AGENTS.md` changes count as documentation. If code, build, or packaging changes
are added later, apply the normal bump policy before committing those changes.

The maintained policy is in [versioning](../versioning.md#bump-policy).

### Positive Consequences

* Documentation work does not require unrelated executable and package edits.
* The versioning guide and contributor instructions follow the owner's policy.

### Negative Consequences

* Authors must check whether later changes make a branch more than documentation-only.
