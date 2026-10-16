# Open the log file without following links, owner-only, and keep truncating it

* Status: accepted
* Date: 2026-10-15

Technical Story: ISO-6 in the 29 September 2026 security audit (the log-file half;
the SQLite, umask and package-script halves landed earlier on this branch).

## Context and Problem Statement

`--log-file` was opened with `std::ofstream(path, std::ios_base::out)`. That follows a
symbolic link in the final component, creates the file with whatever mode the umask
allows, leaves the descriptor inheritable across `exec`, and opens a FIFO or device
just as readily as a regular file (blocking start-up on a FIFO with no reader). The
log carries trace and debug diagnostics, so a world-readable file or a write through
an attacker-placed link both matter. The audit's suggested fix was to create the file
with `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and mode 0600.

## Decision Drivers

* The same path is reused on every start; the server has always truncated it.
* `std::ofstream` cannot be given open flags or a descriptor portably.
* `logger.hpp` is header-only and is linked into executables that do not link the
  observability library.

## Considered Options

* `O_EXCL`, as the audit suggested.
* Open without `O_EXCL`, then accept only a regular file this process owns.
* Keep `std::ofstream` and `chmod` the path afterwards.

## Decision Outcome

Chosen option: open with `O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NOCTTY|O_NONBLOCK`
and mode 0600, then require `S_ISREG` and `st_uid == geteuid()`, `fchmod` it to 0600,
clear `O_NONBLOCK`, and only then `ftruncate` it. Anything else leaves the sink
closed and the logger has no file output. This lives in the header-only
`observability::LogFileSink`, which owns the descriptor and replaces the stream.

`O_EXCL` is rejected because the second start would refuse its own log file. Truncating
is kept because that is what the server has always done; changing it to append is a
separate operator-visible decision. `O_NONBLOCK` exists only so that a FIFO is refused
instead of blocking `open()`; nothing is truncated before the ownership check, so a
hard link to a file this process may write but does not own is left intact.

### Positive Consequences

* A symlinked, special or foreign log path is refused without touching its target.
* The file is 0600 under any umask and the descriptor does not reach exec'd children.

### Negative Consequences

* `--log-file /dev/stderr` and similar symlinked or device paths no longer work; the
  logger writes nothing to the file instead. Use the console sink for that.
* Only the final component is protected; a symlinked parent directory is still
  followed, as for every other operator-supplied path.

## Links

* Related to [ADR-0129](0129-restrict-main-fchmod-to-owner-only-database-mode.md) — main's
  seccomp admits `fchmod` only with mode 0600, which this uses.
