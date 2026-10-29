# Pin third-party GitHub Actions to a full commit SHA

* Status: accepted
* Date: 2026-10-29

Technical Story: SonarQube Cloud rule `githubactions:S7637` (27 open High findings, triaged 2026-10-29)

## Context and Problem Statement

The workflows used third-party actions by tag (`hendrikmuhs/ccache-action@v1.2`,
`crazy-max/ghaction-import-gpg@v6`, `softprops/action-gh-release@v2`, …). Whoever controls an
action's repository can move a tag to other code, and the next workflow run executes it. The
March 2025 `tj-actions/changed-files` compromise worked that way. Here the GPG import action
receives the release signing key and passphrase (`sign-artifacts.yml`), the release action can
write releases, and the codecov and anchore actions receive tokens. Only the SonarSource scan
action was pinned. How should a workflow refer to an action?

## Considered Options

* Pin third-party actions to a full commit SHA, with the release in a trailing comment
* Pin every action, GitHub's own included
* Keep tags

## Decision Outcome

Chosen option: "Pin third-party actions to a full commit SHA, with the release in a trailing
comment", because a commit SHA is the only reference whose code cannot change underneath the
workflow, and the comment (`# v1.2.20`) keeps the pin readable and lets an updater bump it.

The rule is enforced by `tests/tooling/test_workflow_action_pinning.py`
(`workflow-action-pinning-tooling`): every `uses:` whose owner is neither `actions` nor `github`,
and which is not a local `./` workflow, must be `owner/repo@<40 hex digits>` followed by
`# vX.Y.Z`, and one action is pinned to the same commit everywhere it appears. A new third-party
action is added pinned, and an update changes the SHA and the comment together, in every
workflow at once.

### Positive Consequences

* A compromised or retagged third-party action cannot run new code in CI until a reviewed commit
  changes the pin.

### Negative Consequences

* Pins do not follow upstream fixes on their own; someone has to bump them. Nothing in the
  repository does that yet (no Dependabot configuration).

## Pros and Cons of the Options

### Pin every action, GitHub's own included

* Good, because it closes the same hole for `actions/*` and `github/*`.
* Bad, because those are published by the platform that runs the workflow, which can already
  change anything it executes, so pinning them protects against much less. It is not ruled out;
  it was outside the scope of the finding.

### Keep tags

* Good, because a major tag picks up fixes without anyone acting.
* Bad, because it also picks up whatever the tag is moved to, in jobs that hold signing keys and
  release tokens.
