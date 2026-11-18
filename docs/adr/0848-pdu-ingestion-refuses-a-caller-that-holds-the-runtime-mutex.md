# PDU ingestion refuses a caller that holds the runtime mutex

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

Technical Story: the `tsan` job's lock-order-inversion report on `main`, surfaced by PR #600.

## Context and Problem Statement

`homeserver::ingest_pdu_event` takes a room stripe and then `HomeserverRuntime::mutex`. With the stripe held it
releases `runtime.mutex` and takes it back twice: around the missing-history fetch, and around the backend commit of an
event that writes no `current_state` or membership row (ADR-0696), so that independent rooms commit concurrently.

A caller that already holds `runtime.mutex` takes the stripe under it, which reverses the order. Thread A, holding
`runtime.mutex`, waits for room R's stripe; thread B, holding R's stripe, waits to take `runtime.mutex` back after its
commit. Neither proceeds. ThreadSanitizer reported this inversion from `tests/integration/test_join_room_flow.cpp`,
which held the lock across an `ingest_pdu_event` call. Every production caller already drops every level it holds
first (`RuntimeLockRelease`): the inbound `/send` loop, the worker relay, the deferred retry, the pending-join drain and
the join through another resident. Nothing stated or enforced the rule, so a new caller could break it. Should
`ingest_pdu_event` enforce it, and how?

## Considered Options

* Refuse the call: `internal_error`, nothing done, an error logged
* Release the caller's levels inside `ingest_pdu_event` for the whole call
* Document the rule only

## Decision Outcome

Chosen option: refuse the call. `ingest_pdu_event` asks `runtime.mutex.held_by_current_thread()` first and, when it
holds, logs `PDU ingestion refused: the caller holds runtime.mutex` at error level and returns
`PduIngestionStatus::internal_error` without reading or writing anything. The lock order is stated in
`LocalHttpRouter.hpp` beside the declaration. `[lock_order]` in `tests/integration/test_pdu_ingest_commit_window_flow.cpp`
proves the refusal and that the same PDU is accepted with the lock released.

### Positive Consequences

* A caller in the wrong order fails at once, on every run, instead of deadlocking under load or only under TSan.
* The rule sits where a caller reads it.

### Negative Consequences

* A PDU handed in by such a caller is not stored. Every such caller is a defect, and the error log names the event.

## Pros and Cons of the Options

### Release the caller's levels inside `ingest_pdu_event`

It would always work, but the caller holds the lock because it read runtime state under it; releasing it behind the
caller's back invalidates what it read, which is the defect `RuntimeLockRelease` exists to keep visible at the call
site. The production callers already release it themselves, around the call alone.

### Document the rule only

Costs nothing, and is what failed: the test that broke the rule was written after the stripe order was documented in
the function body.
