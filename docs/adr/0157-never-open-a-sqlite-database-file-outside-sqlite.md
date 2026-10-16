# Never open a SQLite database file outside SQLite while connections may be open

* Status: accepted
* Date: 2026-10-16

Technical Story: PR #509 CI. The OpenBSD integration run failed "main key-admission overload survives
real worker socket HTTP and unchanged transaction retry": the federation worker's read-only room reload
failed (`room.reload_failed`), the proxy fell back to main for the retried transaction, and the
duplicate was processed twice. Refines the file checks of DB-10 and ISO-4.

## Context and Problem Statement

POSIX record locks (`fcntl`) belong to a process, not to a descriptor, and closing *any* descriptor of
a file releases *every* lock the process holds on it. SQLite's unix VFS works around this for its own
descriptors: it shares one lock record per inode across a process's connections and defers closing a
descriptor while locks are held. A descriptor opened outside SQLite gets no such care.

`open_sqlite_connection` opened and closed the database file itself on every connection: the
read-write path (`prepare_sqlite_file`, DB-10) to check owner and type and `fchmod` it, the read-only
path (ISO-4) to read the header and refuse WAL. A new pooled write connection opens precisely while
another connection is busy (ADR-0154), and the read-only path runs for each worker room reload and
each media blob read. Each such close silently released a concurrent write transaction's RESERVED
lock. Another process then found a journal with no RESERVED lock, which SQLite treats as hot: a
read-only connection cannot roll it back and fails, and a read-write one would roll back a transaction
still in progress. The scenario "Opening a SQLite connection never releases another connection's write
lock" (`[sqlite-locks]`) reproduces the lost lock on Linux; OpenBSD's timing exposed it in CI.

How do we keep the DB-10 and ISO-4 checks without a descriptor of our own?

## Considered Options

* Check an existing file by name (`fstatat` with `AT_SYMLINK_NOFOLLOW`) and read the header through
  SQLite's own descriptor (`SQLITE_FCNTL_FILE_POINTER`, `xRead`)
* Keep one long-lived descriptor per database file for the life of the process
* Use open file description locks (`F_OFD_SETLK`) through a custom VFS

## Decision Outcome

Chosen option: check by name and read through SQLite, because it removes every descriptor of an
existing database file that is not SQLite's, with public API only.

* `prepare_sqlite_file` creates a missing file with `O_CREAT | O_EXCL` (no connection can hold a lock
  on a file that did not exist) and checks an existing one with `fstatat(..., AT_SYMLINK_NOFOLLOW)`:
  a regular file owned by the effective user. It opens the file only to tighten a mode other than
  `0600`, which happens once, before the first connection, and then confirms the descriptor is the
  inode it checked.
* The read-only path refuses a non-regular file by `lstat`, opens with SQLite, and reads header bytes
  18 and 19 through `SQLITE_FCNTL_FILE_POINTER` before any statement runs. `sqlite3_open_v2` opens the
  file but starts no read transaction, so nothing has looked for WAL yet.

The rule for future code: **nothing in this process opens a SQLite database file except SQLite**, not
for a check, a size or a chmod. Use a path-based call, or SQLite's own file handle.

### Positive Consequences

* A connection opened anywhere in the process no longer releases another connection's locks, so
  another process can no longer mistake a live transaction's journal for a hot one.
* The DB-10 checks (regular file, owner, `0600`, no symlink) and the ISO-4 WAL refusal are unchanged.

### Negative Consequences

* An existing file is checked by name, not through a descriptor, so a file swapped between the check
  and SQLite's open is not caught by the check. SQLite opens with `SQLITE_OPEN_NOFOLLOW`, so a symlink
  is still refused, and swapping a file in the database directory already needs the server's own
  user.
* Tightening a loose mode still opens and closes a descriptor. It happens once, before the first
  connection; a mode loosened while the server runs is tightened at the next connection, at the old
  risk.

## Pros and Cons of the Options

### Keep one long-lived descriptor per file

* Good, because checks could stay descriptor-based.
* Bad, because the descriptor still has to be closed sometime, and every store, test and tool that
  opens the same path in one process would need to share it.

### Open file description locks through a custom VFS

* Good, because OFD locks are not released by closing another descriptor.
* Bad, because OpenBSD and NetBSD have no OFD locks, and a custom VFS is a large surface to own.

## Links

* Refines [ADR-0154](0154-pool-database-write-connections.md): pooled connections open while others
  are mid-transaction, which made the lost lock likely.
