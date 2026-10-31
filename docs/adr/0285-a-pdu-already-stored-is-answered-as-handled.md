# A PDU whose event ID is already stored is answered as handled, before it is verified

* Status: accepted
* Date: 2026-10-30

Technical Story: Complement run 12 (`TestUnrejectRejectedEvents`, `TestSync/parallel/sync_should_succeed_even_if_the_sync_token_points_to_a_redaction_of_an_unknown_event`)

## Context and Problem Statement

A sender may deliver a PDU more than once, in a transaction with a different ID (the transaction ID only
deduplicates a retry of the same transaction), or twice in one transaction. A re-sent PDU passed every receipt
check again, reached `prepare_store_event_with_state`, whose duplicate guard (`event_exists`) refused it, and
`ingest_pdu_event` reported `internal_error`. Since 0.12.63 `/send` writes an `internal_error` into the PDU's
`error` entry (it used to be silent), so the sender was told a PDU this server held had failed. What should a
second delivery of a stored event be answered with, and where is that decided?

## Decision Drivers

* Server-Server API v1.19 "PDU Processing Result": a PDU with no `error` "can be considered successfully
  handled"; "Rejection": a rejected PDU in a transaction must not cause an error response.
* Two transactions racing with the same PDU must not both store it, and the loser must not get an error.
* A real internal error must stay visible to the sender and the operator.
* Signature verification must not be weakened for an event that is not stored.

## Considered Options

* Treat a stored event ID as a duplicate and answer it as handled, with a new `PduIngestionStatus::already_stored`.
* Make the store guard's refusal a non-error (`accepted`) result.
* Re-run the receipt checks on the stored copy and answer with their verdict.
* Keep answering `internal_error` and have senders cope.

## Decision Outcome

Chosen option: "answer it as handled with `already_stored`", because the event was handled when it first
arrived and nothing about the second delivery needs to be done.

* The event ID is looked up (any status: accepted, soft_failed, rejected, outlier) in a room-checked lookup.
  A hit is answered with an empty result, is not verified, authorised or stored again, and has no side effect:
  no stream ordering or sync stream ID, no appservice queueing, no fan-out, no push, no membership projection.
  A stored copy is never re-judged: rejection depends only on the event's own auth events and state before it,
  which its event ID fixes, and `rejected` is stored only when those were resolvable.
* The look-up is made at three points. `FederationRuntimeState::pdu_already_stored` is asked by the `/send`
  handler after the room ACL check and before signature verification (no key lookup for a re-send). Main's
  side of a worker's `pdu_ingest` relay asks `pdu_event_already_stored` before re-verifying the relayed
  signature. `ingest_pdu_event` asks first thing, and again under the room stripe and `runtime.mutex` once any
  missing-history fetch is over. The federation worker's own probe is unset: its event snapshot is not main's
  record of what is stored.
* The second `ingest_pdu_event` look-up is the decisive one. The room stripe and `runtime.mutex` are held from
  it to `prepare_store_event_with_state`, and an ingest applies its event to the in-memory store before it
  releases the stripe, so of two racing copies the loser finds the winner's event there. The store guard stays
  as defence for a writer that does not take the stripe (and still reports failure).
* An event ID held for another room is `rejected_invalid`, never "handled": the ID of a version 3+ event
  commits to its room, so it is not the same event.
* The `/send` handler logs a per-PDU `internal_error` at WARNING level (event ID, room ID, origin, reason) as
  well as auditing it.

### Positive Consequences

* A re-send is cheap and cannot disturb stream positions, sync, push or state.
* A real `internal_error` is distinguishable from a duplicate, in the answer and in the log.

### Negative Consequences

* An outlier stored by `send_join` state or backfill that later arrives as a real timeline event is also
  answered as handled, and is not re-placed by `/send`. Placing an outlier is a separate path.
* A forged copy of a stored event ID (possible only for room versions 1 and 2, whose IDs are not derived from
  the content) is answered "handled" without a signature check. Nothing happens for it, so nothing is gained.

## Pros and Cons of the Options

### Make the store guard's refusal a non-error

* Good, because it is a one-line change.
* Bad, because the PDU would already have been verified, authorised and given a stream ordering, and
  `accepted` makes the sink publish to sync and push again.

### Re-run the receipt checks on the stored copy

* Bad, because the verdict can differ from the first one (state has moved on), so a stored `rejected` event
  would be re-judged and a stored `accepted` one could be answered with an error.
