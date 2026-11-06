# CodeQL drops every result on vendored and build directories

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-06

Technical Story: PR #563's CodeQL check failed on alerts open on `main`, 27 of them high or critical in vendored code

## Context and Problem Statement

`codeql.yml` builds with Meson into `build/`, and the build compiles the Catch2, SQLite and yyjson sources that Meson's
wraps download into `subprojects/`. CodeQL analyses everything the build compiles, so its report on `main` held 503
results in those three projects and 22 more on the compiler probes Meson writes under `build/meson-private/`. Among them
were high and critical alerts (`cpp/path-injection`, `cpp/world-writable-file-creation`,
`cpp/potentially-dangerous-function`, `cpp/suspicious-pointer-scaling`) that nobody here can fix: the code is
upstream's, pinned by the wrap, and changed only by a wrap upgrade. When a pull request is too large for CodeQL to tell
its own alerts from the base branch's, its check counts every open alert, these included, and fails.

ADR-0226 made the exclusion table in `scripts/filter_codeql_sarif.py` the only place a result may be suppressed, each
entry scoped to a rule and a directory. What should happen to results on code this project does not write?

## Decision Drivers

* Every rule must keep covering code this project writes: `src/`, `include/`, `tests/`, `scripts/`.
* A vendored defect is handled by upgrading the dependency, which `docs/dependencies/` and the dependency triage
  workflow already govern; a code scanning alert on it has nobody to act on it.
* Suppression stays in reviewed, tested repository code (ADR-0226), not in alert state on GitHub.

## Considered Options

* Drop every result whose file is under the top-level `subprojects/` or `build/` directory, in the SARIF filter
* Dismiss each vendored alert on GitHub
* Leave them open
* `paths-ignore` in a CodeQL configuration

## Decision Outcome

Chosen option: "Drop every result under `subprojects/` or `build/` in the SARIF filter". `VENDORED_DIRECTORIES` in
`scripts/filter_codeql_sarif.py` names the two directories, and a result whose location is plainly inside one of them
(the same placement rules ADR-0226 set: `%SRCROOT%` base, no `..` segment or backslash) is dropped whatever its rule.
Open alerts there close as fixed at the next analysis of `main`.

This refines ADR-0226's rule: a directory-wide entry, with no rule, is allowed only for a directory that holds no code
this project writes. Never add a directory that does. `subprojects/` tracks only `.wrap` files and Meson overlays in
`subprojects/packagefiles/`; no project source is generated into `build/` (no `configure_file` outside the wraps). A
change that puts project C or C++ in either directory must move it or revisit this ADR.

### Positive Consequences

* The code scanning view shows only alerts on code this project can change.
* Large pull requests stop failing CodeQL on alerts they cannot fix.

### Negative Consequences

* A security defect CodeQL finds in a vendored library is no longer shown. It still reaches the project through
  upstream advisories and the dependency triage workflow, the channels a wrap upgrade is decided by.
* A file generated into `build/` from project code in future would go unanalysed unless this ADR is revisited.

## Pros and Cons of the Options

### Dismiss each vendored alert on GitHub

* Good, because nothing in CI changes.
* Bad, because a wrap upgrade moves the code and raises every alert again, and the decision lives only in alert state.

### Leave them open

* Good, because nothing is hidden.
* Bad, because no one can act on them, and every large pull request fails CodeQL on them.

### `paths-ignore` in a CodeQL configuration

* Good, because it is configuration, not code.
* Bad, because for compiled C++ it does not apply to what the manual build compiles (ADR-0226).

## Links

* Refines [ADR-0226](0226-codeql-drops-unused-static-function-on-catch2-tests-before-upload.md)
* [scripts/AGENTS.md](../../scripts/AGENTS.md) — the filter script
