# A Complement run is judged by a summariser over a checked-in skip list

* Status: accepted
* Date: 2026-10-26

## Context and Problem Statement

Complement will not pass in full against this server: some tests assume
behaviour the spec does not require, some need room versions this server does
not support (ADR-0076), and some will find real gaps. "Green" therefore cannot
mean "every test passed". Complement's own mechanism for this is build tags
(`!dendrite_blacklist`, `!venator_blacklist`) fixed upstream for other servers.
`go test` exits non-zero whenever any test fails, listed or not, and this
project has already shipped work on a tool whose exit status did not mean what
it appeared to mean (`build.py`).

What decides whether a run against a release candidate is green, and what may
a run leave out?

## Decision Drivers

* A failure is either fixed or explained with evidence a reviewer can check.
* An explanation must not outlive the failure it explains, or the list grows
  into a mask.
* Hiding a federation authorisation or signature test is a security decision.
* The run must test what ships, at a fixed Complement revision, in an
  environment the caller's shell cannot alter.

## Considered Options

* A summariser that reads `go test -json`, judged against a checked-in TOML
  skip list in which most entries run and must still fail.
* Passing every listed test to `go test -skip` and trusting the exit status.
* Upstream build tags for this server in Complement.

## Decision Outcome

Chosen option: the summariser, because only a test that runs can show that
its entry has gone stale.

* `scripts/summarise_complement.py` decides. A run is green only when it ran
  tests, every failure is covered by an entry, every `expect-fail` entry still
  fails (one that passes or skips itself is stale), every entry names a test
  that exists, no test was left unfinished (a timeout is a failure and is
  never expected), and no package failed without a failing test (a build
  failure). A parent test whose only failures are listed subtests counts as
  explained. An entry for a parent covers its subtests. `go test`'s exit status
  is recorded, never used.
* `tests/complement/skip-list.toml` entries have a mode:
  * **`expect-fail`** (the default choice): the test runs and must fail.
  * **`skip`**: passed to `go test -skip`. Only for a top-level test that
    would harm the rest of the run, with `not_run_because`. It is checked
    against `go test -list`, and refused if the same name exists in another
    package, which `-skip` would hide too.
* Every entry has one of four categories, each with evidence the summariser
  checks exists: `spec` and `non-spec` cite a file under
  `docs/matrix-v1.19-spec/`, `room-version` cites ADR-0076, and `known-gap`
  names a file under `docs/todos/`. An entry whose test name mentions auth,
  signatures, keys or ACLs needs `signed_off_by`. The match deliberately
  over-includes, because a sign-off is cheap.
* `tests/complement/run.toml` pins the Complement commit, the Go version its
  `go.mod` needs, and the maintainer key fingerprint. `scripts/run_complement.py`
  refuses a package whose digest is not in a `SHA256SUMS` signed by that key
  (`--unsigned` runs a local package, never as evidence). It builds the image
  from a copy outside the source tree, reads the server binary's SHA-256 back
  out of the image, fetches and checks the pinned commit, and drops every
  inherited `COMPLEMENT_*` variable. Its exit status is the summariser's.

### Positive Consequences

* A green run means something specific, and the skip list shrinks as fixes
  land, because a fixed test makes its own entry fail the run.
* A reviewer can check every entry against the spec, an ADR or a todo row.

### Negative Consequences

* A run takes as long as the whole suite, listed failures included.
* The sign-off rule matches by name, so it can miss a security test whose name
  says nothing about auth, signatures, keys or ACLs. Review of each entry is
  still the real control.

## Pros and Cons of the Options

### `go test -skip` for every entry, and the exit status

* Good, because a run is faster and quieter.
* Bad, because a skipped test never runs, so a fixed test keeps its entry for
  ever, and the exit status is non-zero for reasons the list cannot express.

### Upstream build tags

* Good, because it is how Complement handles Synapse, Dendrite and Venator.
* Bad, because every change to the list needs an upstream pull request, and
  tags exclude whole files, not tests.

## Links

* [ADR-0233](0233-complement-runs-the-shipped-trixie-package-in-an-image-that-drops-its-own-privileges.md)
* [ADR-0076](0076-room-versions-1-and-2-are-not-supported.md)
* `tests/complement/AGENTS.md`
