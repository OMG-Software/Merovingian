# Federation worker stale snapshot fallback to main

* Status: accepted
* Date: 2026-10-05

Technical Story: security audit follow-up to DB-2 — a federation worker's PersistentStore is a snapshot taken at worker startup and refreshed per-room via `room_sync` notifications. If a worker reload fails (for example, because the database file is temporarily unavailable), the worker could still serve stale room state for room-scoped reads, violating the authority of main's in-memory state.

## Context and Problem Statement

The out-of-process federation worker holds its own copy of `PersistentStore` to answer federation requests without taking main's `runtime.mutex`. Main keeps the worker fresh by sending a fire-and-forget `room_sync` notification whenever main mutates a room. The worker reloads that room and continues serving requests. Previously there was no observable status for whether a `room_sync` reload succeeded, and `FederationProxy` always forwarded room-scoped requests to the worker regardless of snapshot freshness. If the reload failed, the worker would answer from its stale snapshot while main had newer authoritative state in memory.

## Decision Drivers

* Main's in-memory state must be authoritative for local rooms.
* A failed worker reload must not silently serve stale reads.
* The mechanism must not add latency to the happy path.
* Tests need a test-observable status for room_sync outcomes.

## Considered Options

1. **Keep forwarding to the worker and accept stale reads as a best-effort property.** Matches the current design but violates the security requirement that main's state is authoritative.
2. **Fail every room-scoped request with 503 when the worker snapshot is stale.** Fail-closed but breaks legitimate federation traffic for transient database hiccups.
3. **Track per-room room_sync status and fall back room-scoped reads to main when the status is "failed".** Keeps writes and non-room traffic on the worker, preserves availability for reads, and uses main's authoritative state.

## Decision Outcome

Chosen option: "Track per-room room_sync status and fall back room-scoped reads to main when the status is 'failed'".

Implementation:

* `serialize_room_sync_notification` now carries a monotonically increasing `generation` assigned by main.
* The worker echoes the same `generation` in a new fire-and-forget `room_sync_result` notification after `database::reload_room` completes.
* `WorkerPool` records the latest generation and status (`pending`, `ok`, `failed`) per room, guarded by its own mutex.
* `FederationProxy::room_sync_status(room_id)` exposes this status for tests.
* `FederationProxy::handle` checks the status before forwarding a room-scoped request to the worker; when the status is `failed`, it falls back to `handle_federation_http_request` so main's authoritative state is used.

### Positive Consequences

* Stale worker snapshots cannot override main's current room state for reads.
* The fallback is automatic and requires no operator action.
* Tests can poll `room_sync_status` to observe asynchronous reload outcomes instead of inferring them from logs.

### Negative Consequences

* Main must serve more room-scoped reads during worker snapshot outages, increasing `runtime.mutex` contention.
* The fallback currently applies to any room-scoped request with a failed snapshot. Future work may refine it to reads only if write fallback proves undesirable.

## Pros and Cons of the Options

### Accept stale reads

* Good, because no code change is needed.
* Bad, because it contradicts the design principle that main owns authoritative state.

### 503 on stale snapshot

* Good, because it is strictly fail-closed.
* Bad, because transient reload failures would break federation reads entirely.

### Fallback to main

* Good, because it preserves availability while keeping main authoritative.
* Good, because it reuses the existing direct-path handlers.
* Bad, because it concentrates read load on main during worker snapshot problems.

## Links

* Related to [ADR-0062 - Federation worker holds no secret files](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
* Related to [ADR-0071 - Main re-verifies relayed PDUs](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
* docs/architecture.md "Federation worker room staleness"
