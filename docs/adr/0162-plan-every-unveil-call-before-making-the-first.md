# Plan every unveil(2) call before making the first, and make none if one would fail

* Status: accepted
* Date: 2026-10-17

Technical Story: PR #510 CI, OpenBSD 7.9. With the transaction-dedupe fix in place, the new
scenario "A retried transaction is not processed again when its room moves between the worker
and main" still failed there: every federation worker room reload failed at its open stage
(`room_snapshot.read_failed stage=open`, 6 of 6). The worker's startup load, made before its
runtime applies hardening, succeeded.

## Context and Problem Statement

`apply_openbsd_pledge_unveil` called `unveil(2)` once per profile path and returned false at the
first failure. On OpenBSD the first `unveil` hides every other path from the process, and no
call can be undone. `unveil` fails with `ENOENT` when the directory a path would be created in
is missing. The default BSD profile lists `/var/lib/merovingian`, and OpenBSD has no `/var/lib`.
So the call failed after `/usr` and `/etc/merovingian` had been unveiled. The control reported
failure, but the process kept running with only those two trees visible.

The federation worker hit this whenever `federation.worker.apply_hardening=false`: it does not
harden itself then, so its runtime applies the main profile after loading its store. Its later
room reloads could not see the database in `/tmp` and failed, and the proxy fell back to main
for that room. The main server refuses to start when the control fails, so it was left
half-restricted only until it exited.

How should a sequence of irreversible calls fail?

## Considered Options

* Plan every call first (`openbsd_unveil_rules`) and make none if any would fail
* Skip each path whose parent is missing and unveil the rest
* Keep the per-call loop and abort the process on a failure partway

## Decision Outcome

Chosen option: plan first, because then the process is either fully restricted or not
restricted at all, and the control's reported result matches what the process can see.

* `openbsd_unveil_rules(profile, directory_exists)` lists the calls in order and returns nullopt
  if a path and the directory it would be created in are both missing. It is pure apart from
  the probe it is given, so it is tested on every platform.
* `apply_openbsd_pledge_unveil` makes no `unveil` call unless the whole plan is reachable.
  A failure after that point can only be some other error.

The rule for future code: **a sequence of irreversible process restrictions is checked in full
before its first step.**

### Positive Consequences

* A failed unveil no longer leaves the worker, or main before it exits, unable to see its own
  database.
* The planned calls can be asserted in a unit test off OpenBSD.

### Negative Consequences

* When the plan is refused, the process is not restricted at all; before, it was restricted to a
  broken subset. Main still refuses to start in that case, as before.
* The profile's paths are still fixed defaults. A database, media store or certificate outside
  them is not unveiled, and is invisible once the plan succeeds. This change does not address
  that.

## Pros and Cons of the Options

### Skip unreachable paths

* Good, because the rest of the sandbox still applies.
* Bad, because a skipped writable path can then never be created, and the process would report
  success while missing state it needs.

### Abort on a partial failure

* Good, because no process runs half-restricted.
* Bad, because the worker would crash-loop under its supervisor wherever a default path is
  missing, as it is on stock OpenBSD.

## Links

* Corrects the cause recorded in [ADR-0159](0159-retry-a-false-hot-journal-on-read-only-sqlite-reads.md)
  for the OpenBSD reload failures; that ADR's retry still addresses a real SQLite race.
