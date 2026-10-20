# Warn rather than abort when memory locking fails

* Status: superseded by [ADR-0168](0168-refuse-an-unlocked-master-key.md)
* Date: 2026-09-06

## Context and Problem Statement

`sodium_mlock` on the buffer holding the master key can fail — most commonly
because `RLIMIT_MEMLOCK` is too low for the service. `SecretBuffer` already
recorded whether the lock succeeded, but nothing read it back, so a server
holding its root secret in swappable memory gave no indication anywhere.

## Considered Options

* Log a warning once per process, naming the remedy, and continue
* Refuse to start

## Decision Outcome

Chosen option: "Log a warning once per process and continue", because refusing
to start over a failed `mlock` would turn a hardening shortfall into an outage.

Once per process, not per load: the condition is a deployment-level fault, and
repeating it per load would be noise that gets filtered.

### Positive Consequences

* The remedy is named in the message — raise `RLIMIT_MEMLOCK` or grant
  `CAP_IPC_LOCK`.
* The key is still zeroised on destruction either way; `SecretBuffer`'s
  destructor falls back to plain `sodium_memzero` when the lock did not hold.

### Negative Consequences

* **A server can run to completion with its root secret in swappable memory.**
  The warning is the only signal, so it must not be suppressed by log-level
  configuration in a production profile.

## Links

* [`docs/crypto-boundary.md`](../crypto-boundary.md)

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
