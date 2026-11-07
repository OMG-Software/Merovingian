# ADR numbers are assigned in order, gaps are allowed, and a number is never reused

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-07

Technical Story: Analysis low finding D17, ADR-0000 does not say whether numbering gaps are allowed

## Context and Problem Statement

[ADR-0000](0000-record-architecture-decisions.md) and `AGENTS.md` say to "number it next" and
never to renumber an entry, but neither says what a gap in the sequence means. `docs/adr/` has 73
numbers between 0000 and the highest that have no file. They arose because parallel branches
each reserved the next numbers, and some of those branches never landed. A reader who finds a
gap cannot tell whether a record was lost, deleted or never written, and a contributor cannot
tell whether filling a gap is allowed.

## Considered Options

* Allow gaps, never reuse or renumber a number, and never reference a missing number
* Require a gapless sequence by renumbering when a branch drops its ADRs
* Fill gaps with placeholder records marked as withdrawn

## Decision Outcome

Chosen option: "Allow gaps, never reuse or renumber a number, and never reference a missing
number".

* Numbers are assigned in increasing order. A new record takes a number above every number
  already in `docs/adr/`, or a number from a range reserved for the branch.
* A gap is legitimate. It is a number reserved by a branch that never landed, and it carries no
  meaning. It is not a lost or deleted record.
* A number is never reused, even if the branch that reserved it did not land, and an existing
  record is never renumbered. Renumbering would break every link, changelog entry and source
  comment that cites the number.
* Nothing may cite a number that has no file in `docs/adr/`. A citation of a missing number
  would send the reader to nothing. Cite only records that landed.
* Every file in `docs/adr/` has exactly one row in `index.md`, and every row points to an
  existing file. A gap has no row.

ADR-0000's decision text is not edited, as records are immutable. This record states the rule it
left open.

### Negative Consequences

* The sequence cannot be used to count the decisions made. The index is the list of records.

## Pros and Cons of the Options

### Require a gapless sequence by renumbering

* Good, because the sequence has no holes.
* Bad, because every citation of a renumbered record in other records, source comments, the
  changelog and pull requests becomes wrong.
* Bad, because parallel branches cannot reserve numbers without coordinating.

### Fill gaps with placeholder records

* Good, because the sequence has no holes and a reader sees why.
* Bad, because it adds empty records to the register that carry no decision, against
  [ADR-0000](0000-record-architecture-decisions.md), which limits records to decisions.

## Links

* Refines [ADR-0000](0000-record-architecture-decisions.md) and
  [ADR-0001](0001-use-markdown-architectural-decision-records.md)
