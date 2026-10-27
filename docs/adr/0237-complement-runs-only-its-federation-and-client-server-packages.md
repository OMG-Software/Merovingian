# Complement runs only its federation and client-server packages

* Status: accepted
* Date: 2026-10-27

## Context and Problem Statement

`scripts/run_complement.py` ran `go test ./tests/...` (ADR-0234). That pattern
also matches Complement's `tests/msc*` packages, which test unstable Matrix
spec proposals (MSCs): partial-state joins, delayed events, thread
subscriptions and others. The assumption was that build tags kept them out;
the first full run showed they run by default. Nineteen of its top-level
failures came from them.

This project's authority is Matrix v1.19. A proposal that is not part of it is
not something a release can be held to. Which Complement packages does a
release run?

## Decision Drivers

* A green run must mean "conforms to v1.19", not "implements every proposal".
* The skip list should hold explained exceptions, not a standing list of
  proposals this server never meant to implement.

## Considered Options

* Run `./tests` and `./tests/csapi` only.
* Run `./tests/...` and list each unimplemented proposal's tests as
  `expect-fail` with category `non-spec`.

## Decision Outcome

Chosen option: `./tests` and `./tests/csapi` only (`SPEC_PACKAGES` in
`run_complement.py`), for both the test listing and the run. A proposal this
server implements and wants tested (such as MSC4186 sliding sync, used by
Element X) is added by name, with its own decision, when it is wanted.

### Positive Consequences

* Every failure in a run is against the version of the spec the project
  follows.

### Negative Consequences

* An implemented proposal's Complement tests no longer run by default. Adding
  one is a deliberate change to `SPEC_PACKAGES`.

## Pros and Cons of the Options

### `./tests/...` with skip-list entries

* Good, because nothing is left out silently.
* Bad, because dozens of entries would say only "not in v1.19", and each
  Complement update could add more.

## Links

* Refines [ADR-0234](0234-a-complement-run-is-judged-by-a-summariser-over-a-checked-in-skip-list.md)
* `tests/complement/AGENTS.md`
