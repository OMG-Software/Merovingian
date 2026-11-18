# The version changes only when the owner asks

* Status: accepted
* Date: 2026-11-18

Technical Story: the project owner's instruction of 2026-11-18, while a SQLite fix was being stacked on four open
pull requests (1.1.0 to 1.1.3): "No more auto incrementing versions. We'll only do that when I ask for it."

## Context and Problem Statement

Every branch with a code, build, packaging or test change incremented `BUILD` when it was created
([ADR-0647](0647-versions-from-1-0-0-are-major-minor-build.md)); documentation-only branches did not
([ADR-0464](0464-documentation-only-changes-do-not-require-a-version-bump.md)). With several branches open at once,
each took the next free number, and every rebase of a stacked branch conflicted in the sixteen places that hold the
version and in the CHANGELOG, whose entries git interleaved. The numbers then said how many branches had been made,
not what a release contains. When does the version change?

## Considered Options

* **Only when the owner asks; every change adds its CHANGELOG bullets to the newest version's entry (chosen).**
* Keep one `BUILD` increment per branch.
* Increment once per merge to `main` instead of per branch.

## Decision Outcome

Chosen option: the owner decides, because the owner asked for it, and a version is then a release decision rather than
a by-product of branching.

* No branch changes the version on its own, whatever it changes. A branch keeps the version of the branch it is based
  on, in every location `docs/versioning.md` lists.
* Every change, documentation-only or not, adds its bullets to the newest `# Version` entry of `CHANGELOG.md` under the
  existing headings, and updates that entry's release-notes paragraph when an operator needs to know about it. The
  format rules ([ADR-0741](0741-each-changelog-version-has-features-security-fixes-bug-fixes-and-release-notes.md)) and
  the check that the newest entry is the version `meson.build` declares are unchanged.
* When the owner asks for a version, that change sets the version the owner names in every location together, adds its
  `%changelog` entries to the three RPM specs, and opens a new CHANGELOG entry above the previous one.
* This supersedes ADR-0464, whose exemption no longer has a rule to except, and the per-branch increment of ADR-0647.
  ADR-0647's scheme stands: versions are `MAJOR.MINOR.BUILD`, and `MINOR` and `MAJOR` change when the owner decides.

### Positive Consequences

* Parallel and stacked branches no longer conflict over the version, and the CHANGELOG has one entry to add to.

### Negative Consequences

* Two builds from different commits can report the same version until the owner asks for a new one. The commit, not
  the version string, identifies an unreleased build.

## Pros and Cons of the Options

### One increment per branch

* Good, because every branch's build reports a different version.
* Bad, because of the conflicts and meaningless numbers above, and because the owner no longer wants it.

### One increment per merge to main

* Good, because only merged work moves the number.
* Bad, because a merge still picks a number nobody chose for a release, and someone has to make the change at merge
  time, which the project has no step for.

## Links

* Supersedes [ADR-0464](0464-documentation-only-changes-do-not-require-a-version-bump.md)
* Partly supersedes [ADR-0647](0647-versions-from-1-0-0-are-major-minor-build.md): the per-branch `BUILD` increment
* [docs/versioning.md](../versioning.md)
