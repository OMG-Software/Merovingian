# Retry worker spawn failures without waiting on unrelated children

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Audit ISO-3 found that a failed restart left the supervisor with PID -1.
Calling `waitpid(-1)` then either reaped another supervisor's child or returned
ECHILD and permanently ended supervision. Resetting backoff immediately after
spawning also allowed a crashing child to restart every second indefinitely.

## Considered Options

* Keep retry state in the supervisor loop and wait only on its owned positive PID.
* End supervision after a failed spawn and require an operator restart.
* Reset backoff whenever spawning succeeds.

## Decision Outcome

Retry failed spawns while supervision is running, independently of child waiting.
Only a positive owned PID may be passed to `waitpid`. Tear down the old IPC
channel outside its ownership mutex before retrying. Backoff doubles from one
second to a maximum of 30 seconds and resets only after 30 seconds of continuous
child and IPC health. Wait in steps of at most 100 milliseconds so shutdown
interrupts even the maximum backoff.

A successful spawn alone is insufficient evidence of recovery: the executable
can immediately crash or fail its IPC handshake. Ending supervision after a
temporary executable or resource failure would unnecessarily require operator
intervention and leave the configured federation pool degraded.

### Positive Consequences

* Temporary spawn failures recover when their cause disappears.
* One supervisor cannot reap another supervisor's child.
* Repeated crashes retain bounded retry pressure and prompt shutdown.

### Negative Consequences

* Recovery after several consecutive failures waits for the accumulated backoff.

## Links

* [Security audit](../security-audit-report-2026-09-29.md)
