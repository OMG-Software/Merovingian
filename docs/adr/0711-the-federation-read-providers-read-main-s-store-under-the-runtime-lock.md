# The federation read providers read main's store under the runtime lock

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

`handle_federation_http_request` calls the federation core without `runtime.mutex` on purpose, so a whole `/send`
transaction does not hold it. The read providers it installs (server ACL, room version, state, state_ids, event_auth,
backfill, get_missing_events, event) read `persistent_store` with no lock. In a federation worker they are wrapped by
`StoreReadGuard`, but in main nothing wraps them and every writer changes the store under `runtime.mutex` only. An
EDU-only `/send` answered by main, a room whose worker sync failed, or a deployment without a worker could therefore read a
vector or hash table while it was reallocated (run-3 finding C11).

## Considered Options

* Each provider takes `runtime.mutex` itself in main, through one helper
* Install a main-side equivalent of `StoreReadGuard` after wiring
* Hold the lock in the federation core around the provider calls

## Decision Outcome

Chosen option: "Each provider takes `runtime.mutex` itself in main". `main_store_read_lock` returns the lock, or an empty
lock when `federation_policy_decided_upstream` is set (a worker, which answers from its own snapshot under
`StoreReadGuard`). It is the same pattern `timestamp_to_event_query_provider` already uses. The providers do no network
I/O, so the lock is never held across any, and the mutex is recursive, so a caller that holds it is unaffected.

Why not a `StoreReadGuard` for main: it protects against the reload swap, not against writers, and main has no swap.
Why not lock in the federation core: it would hold the lock over signature work and the rest of the transaction, which is
what the design avoids.

Residual: a large `/state` or `/backfill` answer is built under the lock, bounded by the answer limits those builders
already apply (ADR-0363, ADR-0364).
