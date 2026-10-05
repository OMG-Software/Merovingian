# Configure operational budgets with shared recovery bounds

* Status: accepted
* Date: 2026-10-05

## Context and Problem Statement

A single local user can receive large federated room state, device-key traffic and parallel client requests. Hard-coded 1,000-ID state recovery caps reject legitimate large-room responses, while separately configured transaction bytes are shadowed by smaller HTTP and IPC limits. Raising each local recovery counter independently can multiply work across an incoming PDU's missing references.

## Considered Options

* Raise constants without changing configuration or cumulative work accounting.
* Remove operational limits.
* Expose finite validated operational policies, compose byte caps across transports, and share recovery accounting across one incoming PDU.

## Decision Outcome

Chosen option: "Expose finite validated operational policies, compose byte caps across transports, and share recovery accounting across one incoming PDU", because operators need workload-specific controls without accidental unlimited network work or hidden smaller transport caps.

Advertised state/auth ID capacity is independent of network calls: locally cached events consume ID capacity but require no fetch. General and snapshot recovery retain separate call caps, with a shared total-call cap and deadline across the entire recovery attempt. Failed attempts consume calls. Exhausting the call budget prevents another request but does not discard the successful last response. Deadline checks stop subsequent processing and shorten outbound HTTP timeouts; they do not preempt an individual synchronous discovery, verification or database operation.

HTTP admission uses the configured federation `/send` transaction size. Both worker IPC endpoints derive the same frame ceiling from request-body/head escaping and response-body base64 expansion. Raising a policy cannot silently leave an older smaller IPC ceiling in place.

Recovered snapshots must also be usable during subsequent fork resolution. The resolver therefore receives a separate finite policy for group, entry, key, mainline and auth-walk counts, with an aggregate submitted-entry cap checked before indexing. Increasing only per-group capacity would otherwise multiply allowed work by the number of groups. This policy applies to local and federated event bookkeeping alike and does not weaken authorization or replace failed resolution with partial state.

Startup-snapshotted limits require restart. A reload plan must not describe a setting as applied through SIGHUP unless its live consumers are rebuilt. Matrix's protocol maxima and cryptographic validation remain mandatory; parser and sandbox structural boundaries remain implementation safety constraints.

### Positive Consequences

* Operators can tune normal traffic and large-room recovery without rebuilding binaries.
* A larger state-ID allowance does not authorize an unlimited number of remote calls.
* Configuration, transport admission and worker framing agree on capacity.

### Negative Consequences

* Larger defaults consume more memory, threads and outbound work; they need deployment measurement.
* Recovery can still fail on deadline/call/body caps or remote errors. Durable retention and retry of ordinary unresolved PDUs remains separate unfinished work.
* Deployment tuning requires a restart of main and workers.

## Links

* [Operator budgets](../user-manual.md#operational-budgets)
* [Bounded request-time recovery](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
