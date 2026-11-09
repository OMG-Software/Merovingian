# The SQLite path comes only from operator configuration

* Status: accepted
* Date: 2026-11-09

Technical Story: SonarCloud `cppsecurity:S2083` (path injection) on PR #570.

## Context and Problem Statement

`prepare_sqlite_file` creates and opens the path it is given without filtering it. SonarCloud reports that as path
injection, tracing a value from a client request to the two `openat` calls.

The trace does not follow the path. It marks the whole `PersistentStore` as tainted because a request handler passes
the store along, then reaches `store.sqlite_path` through it. No request value is ever written to that field. It is
assigned once, when `open_sqlite_persistent_store` opens the store with `config.database().sqlite_path`, which the
config parser reads from `database.sqlite_path` in the operator's file.

What the code depends on is therefore not stated where the path is used: the path is trusted because of where it
comes from.

## Considered Options

* Keep trusting the operator's path and dismiss the report as a false positive
* Confine the path to an allow-listed directory
* Restructure the calls until the analyser's trace no longer connects

## Decision Outcome

Chosen option: "Keep trusting the operator's path and dismiss the report as a false positive", because the operator
chooses where the data lives and no client can influence that choice.

`PersistentStore::sqlite_path` is set only when the store is opened, from operator configuration. It must never be
derived from a request, a federation message, an admin API body or a database row. A change that would do so has to
add its own confinement first.

`prepare_sqlite_file` still defends against the filesystem itself: a symlink in place of the database file, a directory
created by someone else, a file owned by another user. Those checks address local races and do not depend on this
decision.

### Negative Consequences

* The report stays open until the project owner dismisses it, because closing a finding needs a SonarCloud token.

## Pros and Cons of the Options

### Confine the path to an allow-listed directory

* Good, because a future mistake that let a request reach the path would be contained.
* Bad, because operators keep data in places the server cannot predict, including through a symlinked data directory
  (PR #509 review).

### Restructure the calls until the analyser's trace no longer connects

* Good, because the report would go away without an owner step.
* Bad, because the code would become harder to read and no safer, and the next analysis could report it again.
