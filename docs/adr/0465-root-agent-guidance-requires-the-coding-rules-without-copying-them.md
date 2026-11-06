# Root agent guidance requires the coding rules without copying them

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

The root `AGENTS.md` repeated coding requirements in its general rules,
delegation briefs, and naming conventions. Separate copies can diverge from
`docs/coding-rules.md`. The project owner requested that the root file remove
coding rules while still requiring contributors to follow that guide.

## Considered Options

* Maintain coding rules in both the root instructions and the documentation.
* Require the coding guide from the root instructions without copying its rules.
* Leave the coding guide as an optional reference.

## Decision Outcome

Chosen option: require the coding guide without copying its rules. The root
instructions require contributors and delegated agents to read and follow
[coding rules](../coding-rules.md) before code or test work. Delegation briefs
must reference the same requirements. Completion includes checking the change
against that guide and reporting unmet requirements.

Move any unique naming conventions into the coding guide before removing the
root copy. Keep project information, workflow, verification, delegation, and
reference material in the root file. Directory instructions retain their
module-specific guidance; the security and testing guides remain required
through the coding guide.

### Positive Consequences

* One maintained copy defines project-wide coding rules.
* The coding guide is a binding requirement rather than optional reading.
* Delegates receive the same source as the orchestrator.

### Negative Consequences

* Contributors must open the guide before code work.
* A broken link or missing guide blocks work until the source is restored.
