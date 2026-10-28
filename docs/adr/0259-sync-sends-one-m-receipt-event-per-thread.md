# /sync sends one m.receipt event per thread

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (C4)

## Context and Problem Statement

One `m.receipt` content has one slot per user, receipt type and event, so a user's unthreaded and threaded `m.read` for the same event collapsed into one and a client lost a receipt.

## Considered Options

* One `m.receipt` event per thread categorisation (unthreaded, `main`, each thread root)
* Merge into one event and keep the latest

## Decision Outcome

Chosen option: "One `m.receipt` event per thread categorisation (unthreaded, `main`, each thread root)", because the spec says receipts "SHOULD be batched into one event per room and thread", and merging loses one. `ReceiptContentBuilder::build_per_thread()` builds them; `build()` remains for sliding sync, which still holds one event per room.

### Positive Consequences

* Both receipts reach the client.

### Negative Consequences

* Sliding sync's receipts extension keeps the latest receipt on such a clash.
