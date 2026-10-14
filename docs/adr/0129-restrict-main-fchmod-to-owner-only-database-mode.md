# Restrict main's fchmod to owner-only database mode

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

SQLite file admission validates an opened descriptor's type and owner and uses
`fchmod(fd, 0600)` to tighten its permissions (DB-10). The main-process seccomp
profile denied `fchmod`, causing SIGSYS during store initialization and server
startup in the combined tests. Disabling seccomp or admitting arbitrary permission
changes would undo a separate hardening boundary.

## Considered Options

* Allow `fchmod` only in main and only with mode exactly `0600`.
* Allow arbitrary `fchmod` in main and both worker profiles.
* Remove permission tightening or defer it to a path-based operator action.

## Decision Outcome

Chosen option: "Allow `fchmod` only in main and only with mode exactly `0600`".
The main BPF program checks the mode argument and restores the syscall-number
accumulator before subsequent entries. Both worker profiles continue to deny
`fchmod` entirely; path-based chmod and ownership mutation remain denied.
Main's separate private-only umask grant is recorded in ADR-0130.

### Positive Consequences

* Owned database files can be tightened through the validated descriptor without
  reopening by path or allowing symlink replacement to redirect chmod.
* Database initialization remains possible under the production filter.
* Broader modes, including group/other access and setuid bits, are refused.
* Forked kernel tests cover main admission and denials across all three profiles.
  Constant-only allowlist inspection cannot verify argument-restricted entries.

### Negative Consequences

* Seccomp checks descriptor numbers, not database identity: main can apply `0600`
  to any descriptor it can otherwise obtain. Type and owner validation remain
  the database loader's responsibility. This is not a file-specific grant.
* An owned read-only file could become owner-writable. The restriction guarantees
  no group/other access, not decreasing owner permissions. Workers do not retain
  this capability after installing their stricter filters.

## Pros and Cons of the Options

### Allow arbitrary fchmod

Rejected because it permits wider permissions and unnecessary worker metadata
mutation merely to satisfy one database operation.

### Remove permission tightening

Rejected because private creation does not secure existing permissively owned
database files. Path-based chmod also discards the descriptor identity guarantee.

## Links

* [Runtime hardening](../hardening.md)
* [29 September 2026 security audit](../security-audit-report-2026-09-29.md)
