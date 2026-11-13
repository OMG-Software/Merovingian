# Each changelog version has Features, Security Fixes, Bug fixes and Release notes

* Status: accepted
* Deciders: project owner
* Date: 2026-11-12

Technical Story: owner request on the 1.0.1 branch: "Changelog format is wrong. it should be as follows. (Fix it and
record the format in the docs)", followed by a template of `# Version x.y.z` with `## Features`, `## Security Fixes`,
`## Bug fixes` (bullets of at most two lines each) and `## Release notes` (a short paragraph).

## Context and Problem Statement

Through the 0.x series every version was a `## X.Y.Z` section of free narrative: one `###` subsection per change,
each several paragraphs long, explaining the fault, the fix and its tests. The 1.0.1 entry ran to over 470 lines. An
operator deciding whether to upgrade could not find what changed for them, which fixes were security fixes, or what
they had to do first. What shape does each version's entry take?

## Decision Drivers

* An operator reads the changelog to decide whether, and how, to upgrade.
* Security fixes must be visible at a glance, apart from other corrections.
* The reasoning behind a change already has a home: the ADR, the commit message and the audit report.
* A rule only holds if something checks it.

## Considered Options

* Four fixed headings per version, short bullets, one release-notes paragraph
* Keep the narrative `##`/`###` format of the 0.x series
* Keep a Changelog's six categories (Added, Changed, Deprecated, Removed, Fixed, Security)

## Decision Outcome

Chosen option: four fixed headings, because it is the owner's format and it answers the operator's three questions
(what is new, what was a security fix, what must I do) in fixed places. Each version is `# Version x.y.z` with exactly
`## Features`, `## Security Fixes`, `## Bug fixes` and `## Release notes`, in that order. Bullets are at most two lines
at the 120-column wrap and name the ADR or finding they rest on; a section with nothing in it keeps its heading and
says `* None.` or where the work shipped. Release notes are one paragraph and carry upgrade steps and known
limitations. `docs/versioning.md` ("Changelog format") states the rules and `tests/tooling/test_changelog_format.py`
enforces them, including that the newest entry is the `meson.build` version.

### Rejected

* **The 0.x narrative format.** It reads well per change and keeps the full reasoning beside the version, which is
  why it looks better in isolation. But the reasoning is a copy of the ADR, the security fixes are not told apart from
  test fixes, and an upgrade step is buried in whichever subsection introduced it.
* **Keep a Changelog's categories.** Widely known, but "Changed", "Deprecated" and "Removed" split what this project
  treats as one question (what is new for the operator), and it has no place for release notes.

### Consequences

* 1.0.0 and 1.0.1 were rewritten into the format. `CHANGELOG-pre-release.md` keeps the old format; it is frozen
  (ADR-0740).
* A documentation-only change, which keeps the current version, adds a bullet to that version's `Features` (new
  guidance) or `Bug fixes` (a correction); there is no longer a `Documentation` section.
* A test or CI fix goes under `Bug fixes`; a hardening change with no vulnerability behind it is a `Feature`.
* The detail that used to be in the changelog must be in the ADR or commit message, so a bullet that cannot name an
  ADR, finding or commit should make the writer ask whether the reasoning was recorded anywhere.
