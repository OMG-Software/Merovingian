# Bound sync waits before handing off the connection

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Audit HTTP-4 found that one account could occupy all 32 sync workers. A timeout
ceiling limits duration but does not limit concurrent waits. A refused sync-pool
submission also waited on a main request worker, defeating pool separation.

## Considered Options

* Admit waits with shared account and device budgets, and refuse excess requests.
* Cancel an older wait when another request arrives from its device.
* Rely on the existing request-rate limit and timeout ceiling.

## Decision Outcome

Use nonblocking RAII admission in the transport before submitting a wait. Both
v3 sync and sliding sync supply authenticated user and device identities from
dispatch under the runtime lock. They share budgets: at most four waits per
account, two per device, and at most the sync-pool worker count globally (capped
at 32). Smaller pools reduce the per-account limit to one quarter of the pool,
with a minimum of one. Slots include queued work and remain held through the
response; disconnect, exceptions and failed submission release them.

Excess requests and refused pool submissions get 429 `M_LIMIT_EXCEEDED` with
`retry_after_ms`. A refused submission never waits on the main pool. The
existing 120-second timeout ceiling applies independently.

Cancellation was rejected because regular sync and multiple sliding-sync
connections legitimately share a device. Cancelling a device's previous poll
would disrupt a different connection, while admitting its replacement before
the old task exits would leave actual resource use unbounded. Refusal keeps
existing legitimate waits intact and gives clients explicit backpressure.

### Positive Consequences

* A single account cannot occupy the production sync pool.
* Admission memory is bounded by live slots; token rotation cannot create a new account budget.
* Pool saturation cannot spill blocking waits into the main request pool.

### Negative Consequences

* Clients running more than two simultaneous waits per device must retry.
* Aggregate saturation still refuses new waits; this is bounded load shedding,
  not a guarantee that arbitrary numbers of clients can wait concurrently.

## Links

* [Audit HTTP-4](../security-audit-report-2026-09-29.md#http-4-sync-timeout-has-no-upper-bound-and-there-is-no-per-user-cap-on-long-polls)
