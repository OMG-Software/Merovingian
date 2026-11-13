# The Complement blocker is also waived for 1.0.1

* Status: accepted
* Date: 2026-11-13

## Context and Problem Statement

[ADR-0648](0648-the-complement-blocker-is-waived-for-1-0-0-only.md) waived the green Complement run for 1.0.0 only, and
`docs/release-process.md` said the waiver applies to no later release.

1.0.1 fixes the 49 findings of the run-3 security audit of the 1.0.0 release candidate, 9 of them high. The 1.0.0 release
ships those vulnerabilities, so the owner decided on 2026-11-13 to tag 1.0.1 at once and remove the 1.0.0 release. No
Complement run exists for 1.0.1. Can 1.0.1 be tagged without one?

## Considered Options

* Waive the blocker for 1.0.1 as well; it stays open for every later release
* Hold the 1.0.1 tag until a green Complement run exists

## Decision Outcome

Chosen option: "Waive the blocker for 1.0.1 as well".

What is waived: the green Complement run before the 1.0.1 tag. 1.0.1 carries no Complement evidence and no signed
Complement record is attached to it.

Why: the only published release, 1.0.0, has known vulnerabilities and 1.0.1 fixes them. Holding the fix for a Complement
run would leave 1.0.0 as the only release to install. The run-3 audit and this project's own suites gate 1.0.1, as the
run-2 audit gated 1.0.0.

What still applies:

* The blocker stays open in `docs/todos/production-milestone.md`.
* 1.0.2 and every later release follow `docs/release-process.md` as written, including a green Complement run before the
  tag. This waiver is no precedent for them.
* The 1.0.0 GitHub release is deleted, because it ships the vulnerabilities 1.0.1 fixes. The `v1.0.0` tag stays: a tag is
  never moved or removed once something was published under it, and ADR-0651 cites it.

### Negative Consequences

* Federation conformance for 1.0.1 rests on this project's own tests and the audit. No external check supports it.

## Pros and Cons of the Options

### Hold the 1.0.1 tag until a green Complement run exists

* Good, because it follows the release process as written.
* Bad, because the vulnerable 1.0.0 stays the only release until a run is green, and no green run has ever been recorded.

## Links

* [ADR-0648](0648-the-complement-blocker-is-waived-for-1-0-0-only.md),
  [ADR-0651](0651-the-v1-0-0-tag-moves-to-the-release-workflow-fix-without-a-version-bump.md),
  [ADR-0235](0235-complement-evidence-is-a-maintainer-signed-record-tied-to-the-shipped-binary.md)
* [docs/release-process.md](../release-process.md), [docs/todos/production-milestone.md](../todos/production-milestone.md)
