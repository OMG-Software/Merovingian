# The changelog starts at 1.0.0, and the pre-release entries are a frozen record

* Status: accepted
* Deciders: project owner
* Date: 2026-11-12

Technical Story: owner request on the 1.0.1 branch: "Rename the CHANGELOG to be CHANGELOG-pre-release.md - it should
contain change entries pre v1.0.0. A new CHANGELOG should be in place starting with v1.0.0".

## Context and Problem Statement

By 1.0.1, `CHANGELOG.md` held nearly 11,000 lines: 182 sections of the 0.x series and two of production releases.
The documentation site publishes it as its changelog page, and the README sends an operator to it for a release's
known limitations. Most of what an operator scrolled through described versions nobody runs, since the project had
no users before 1.0.0. Where do the 0.x entries go, and where do new entries go?

## Decision Drivers

* An operator reading the changelog wants the production releases.
* The 0.x entries are the record behind many ADRs and audit write-ups, so they are kept, unedited.
* One file takes new entries, so a contributor never has to choose.

## Considered Options

* Split at 1.0.0: `CHANGELOG.md` from 1.0.0 onwards, `CHANGELOG-pre-release.md` for the 0.x series, frozen
* Keep one file and add a table of contents
* Delete the 0.x entries and leave them to the git history

## Decision Outcome

Chosen option: split at 1.0.0. `CHANGELOG.md` holds 1.0.0 and every later version, newest first, and is the only
changelog that is added to. `CHANGELOG-pre-release.md` holds 0.12.93 and everything before it, exactly as written, and
nothing is added to it or changed in it. The file was moved with `git mv` so `git log --follow` keeps the 0.x history.
The documentation site still publishes `CHANGELOG.md` alone as its changelog page; its link to the pre-release file
opens on GitHub, as the site's hooks do for every file the site does not publish.

### Rejected

* **One file with a table of contents.** It leaves the length, and the site page, as they were.
* **Deleting the 0.x entries.** Documents in `docs/todos/` and the ADRs point at 0.x sections ("see the 0.12.13
  section"); git history is not a document a reader can follow a link to.

### Consequences

* A reference to a 0.x section names `CHANGELOG-pre-release.md`; live documents that pointed at `CHANGELOG.md` for one
  were changed. Records are not: an ADR that cites "`CHANGELOG.md`, 0.12.5" (ADR-0026 and others) or an RPM
  `%changelog` entry that says "see CHANGELOG.md 0.12.x" stays as written, and a 0.x version number always means the
  pre-release file.
* `scripts/check-staged-changelog-docs.sh` still requires `CHANGELOG.md` with every project change; staging only the
  pre-release file does not satisfy it.
