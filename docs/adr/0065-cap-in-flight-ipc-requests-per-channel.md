# Cap in-flight IPC requests per channel

* Status: accepted; the reader-side dispatch queue in front of this cap, left unbounded here, is bounded by [ADR-0111](0111-bound-the-ipc-dispatch-queue.md)
* Date: 2026-09-24

## Context and Problem Statement

ADR-0027 left the federation worker's IPC dispatch pools unbounded because it treated the worker's supervisor as a trusted, self-limiting producer. After the 0.12.12 security audit (finding N1), the federation worker is the least-trusted process in the system: it holds no secret files, but it is still sandboxed precisely because a compromise must not take down the whole homeserver. ADR-0027's premise is therefore false for the IPC pools — the producer is the untrusted worker, and an unlimited IPC queue lets a compromised worker flood main until it is OOM-killed, taking client traffic with it.

The question is how to bound IPC work from the worker without silently dropping PDUs.

## Decision Drivers

* A compromised or pathological worker must not be able to exhaust main's memory through queued IPC handlers.
* A dropped PDU is not acceptable; federation relies on the remote retrying a failed transaction.
* The cap must not require a global lock that serialises all worker shards.

## Considered Options

1. **Global handler-pool queue depth cap** — bound the `net::ThreadPool` that runs all IPC handlers.
2. **Per-channel cap on in-flight requests** — count requests currently being handled on each worker's IPC channel and reject new ones on that channel with an explicit error reply.

## Decision Outcome

Chosen option: **per-channel cap on in-flight requests**.

Each `IpcChannel` exposes `set_max_in_flight`, `try_acquire_in_flight`, and `release_in_flight`. `WorkerPool` configures the cap on every supervisor channel from `federation.worker.ipc_max_in_flight_requests` (default 256), acquires a slot before queuing a handler, and releases it when the handler finishes. Requests over the cap receive an explicit error reply *without* being queued:

* `pdu_ingest` replies with `{"status":"main_overloaded"}`.
* `membership_ingest` and `invite_ingest` reply with `{"accepted":false,"status":503}`.
* Other request types receive appropriate error frames.

The worker maps `main_overloaded` to a retryable HTTP 503 toward the remote, so the transaction is retried rather than dropped.

### Positive Consequences

* A flooded worker can only occupy `ipc_max_in_flight_requests` slots per channel, capping memory regardless of how fast it sends frames.
* The error is explicit and per-channel: one flooded shard cannot starve another shard's traffic.
* Federation semantics are preserved: 503 causes the remote to retry, matching the design goal of ADR-0027.

### Negative Consequences

* Two different backpressure mechanisms now apply to adjacent layers: the connection queue remains bounded globally (ADR-0027), while the IPC layer is bounded per-channel (this decision).
* Under overload the remote retries the whole transaction, so some duplicate work is possible; duplicate event IDs are already handled idempotently by the ingestion sink.

## Pros and Cons of the Options

### Global handler-pool queue depth cap

* Good, because it is simple and uses the existing `ThreadPool::submit` backpressure.
* Bad, because it mixes traffic from all worker shards in one global counter; a flood on one shard would drop or delay work from every other shard.
* Bad, because it silently drops requests unless each request type is given a separate error response path, which is harder than a per-channel semaphore.

### Per-channel cap on in-flight requests

* Good, because isolation between shards is preserved.
* Good, because the acquiring thread can immediately send the correct type-specific overload reply.
* Bad, because it adds a second concurrency primitive (per-channel counter) alongside the thread pool.

## Links

* Supersedes the IPC-pool half of [ADR-0027](0027-bound-the-connection-queue-but-not-the-ipc-queue.md); the connection-queue half of ADR-0027 remains in force.
* `CHANGELOG.md`, 0.12.13
