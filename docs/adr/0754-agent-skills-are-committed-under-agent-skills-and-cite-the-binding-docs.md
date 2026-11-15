# Agent skills are committed under .agent/skills and cite the binding docs

* Status: accepted
* Date: 2026-11-14

## Context and Problem Statement

Reviews of this project's changes keep missing the same things. Code holds `runtime.mutex` across I/O or unbounded
work. A handler is added to main without its federation worker path. A test passes with the fix reverted. A branch
updates the user manual but not the owning guide. A general-purpose review skill knows none of this. A
project-specific review skill does, and it has to live somewhere every session, worktree and contributor can reach.
It also has to stay consistent with the rules it checks against.

## Considered Options

* `.claude/skills/` in the repository
* The reviewer's own user-level skill directory
* `.agent/skills/`, committed with the code
* A skill that restates the coding, security and testing rules in full

## Decision Outcome

Chosen option: `.agent/skills/`, committed with the code. The first skill is
`.agent/skills/merovingian-review/`. The skill is a method and a checklist. Its reference files point at the
binding text by `path#heading` and ADR number, and they do not restate the rules. Where a reference and the
document it cites disagree, the document wins, and the disagreement is a defect in the skill. The same principle
is set for the root guidance in [ADR-0465](0465-root-agent-guidance-requires-the-coding-rules-without-copying-them.md).
The `docs/AGENTS.md` update table gives the skill a row, so a change to anything it cites updates it in the same
branch.

### Positive Consequences

* Every worktree, CI agent and contributor reviews against the same, versioned checklist.
* The skill is reviewed and changed through pull requests like the code it describes.
* A rule change lands in one binding document; the skill's pointer to it stays valid.

### Negative Consequences

* Tools that discover skills only under `.claude/skills/` do not find it on their own. The root `AGENTS.md` names
  the skill, and a contributor may link it into their own skill directory.
* Heading-based citations break when a cited heading is renamed. A reviewer who finds a dead citation fixes the
  skill in the same branch.

## Pros and Cons of the Options

### `.claude/skills/` in the repository

* Good, because Claude Code discovers it with no setup.
* Bad, because `.claude/` is ignored by `.gitignore`. The skill would exist in one checkout only, and worktrees
  under `.worktrees/` and `.claude/worktrees/` would not see it.

### The reviewer's own user-level skill directory

* Good, because every checkout on that machine sees it.
* Bad, because it is not versioned with the code. Other contributors and CI agents do not have it, and nothing
  keeps it in step when a rule changes.

### A skill that restates the rules in full

* Good, because a reviewer reads one file.
* Bad, because two copies of a rule drift apart. The root `AGENTS.md` dropped its copies for that reason
  (ADR-0465).

## Links

* Refines [ADR-0465](0465-root-agent-guidance-requires-the-coding-rules-without-copying-them.md)
