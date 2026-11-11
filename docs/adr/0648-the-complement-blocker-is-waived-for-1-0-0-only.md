# The Complement blocker is waived for 1.0.0 only

* Status: accepted
* Date: 2026-11-11

## Context and Problem Statement

`docs/todos/production-milestone.md` has one blocker for 1.0.0: "Federation conformance is entirely self-attested". It is
done when Complement runs green against a release candidate. `docs/release-process.md` requires that green run before the
tag ([ADR-0235](0235-complement-evidence-is-a-maintainer-signed-record-tied-to-the-shipped-binary.md)).

No green run was ever recorded. The last, run 18 at 0.12.64, had one unexpected failure: a restricted-join power-level
latency race. The owner decided on 2026-11-10 and 2026-11-11 to tag 1.0.0 anyway. Can 1.0.0 be tagged, and what does that
change for later releases?

## Considered Options

* Waive the blocker for 1.0.0 only; the blocker stays open
* Close the blocker
* Hold the tag until a green run exists

## Decision Outcome

Chosen option: "Waive the blocker for 1.0.0 only".

What is waived: the requirement of a green Complement run before the 1.0.0 tag. 1.0.0 carries no Complement evidence and
no signed Complement record is attached to it.

Why: the owner chose a security audit as the 1.0.0 gate instead. Release-gate audit run 2, at commit 279d4a0b, confirmed
39 findings (8 high, 14 medium, 15 low, 2 informational) and left 3 needing validation. All were fixed in 0.12.91 to
0.12.93, before this release.

What still applies:

* The blocker is not closed. It stays open in `docs/todos/production-milestone.md` for later releases.
* Later releases follow `docs/release-process.md` as written, including a green Complement run before the tag.
* The waiver covers 1.0.0 only. It is not a precedent for any other version.
* The 1.0.0 changelog lists the missing Complement evidence as a known limitation.

### Negative Consequences

* Federation conformance for 1.0.0 rests on this project's own tests and the audit. No external check supports it.

## Pros and Cons of the Options

### Close the blocker

* Bad, because no green run exists. Closing it would say something false.

### Hold the tag until a green run exists

* Bad, because the owner decided not to wait.

## Links

* [ADR-0235](0235-complement-evidence-is-a-maintainer-signed-record-tied-to-the-shipped-binary.md)
* [docs/todos/production-milestone.md](../todos/production-milestone.md), [docs/release-process.md](../release-process.md)
