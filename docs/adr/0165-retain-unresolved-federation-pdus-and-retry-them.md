# Retain unresolved federation PDUs and retry them

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-17

Technical Story: audit finding R03 (a PDU whose history cannot be fetched is lost after a 200)

## Context and Problem Statement

`ingest_pdu_event` returned `PduIngestionStatus::missing_prev_state` without storing the PDU when a `prev_event` or
`auth_event` was unknown and a single bounded backfill did not find it, or when a `prev_event` had no state group.
`PUT /_matrix/federation/v1/send/{txnId}` counted that status, recorded the transaction in the dedup ring and answered
`200` with no entry for the PDU. The sender treated the PDU as handled and moved on, a resend of the transaction was
deduplicated, and nothing on this server ever tried again. The event was lost unless some unrelated later backfill
happened to fetch it.

The spec (server-server-api.md, "Transactions") says the `200` response maps each PDU to its processing result and that
a PDU with no error "can be considered successfully handled". Gap filling is this server's job, through
`/get_missing_events` and `/backfill`. How does a server that cannot place a PDU *yet* honour both?

## Decision Drivers

* A remote server chooses what arrives. Whatever is kept must be bounded, and the bounds must not depend on the sender.
* A restart must not lose what was promised as handled.
* One PDU that cannot be placed must not block or fail the rest of its transaction.
* Signatures are verified before ingestion; a retry must not weaken that.

## Considered Options

* Retain the PDU durably, bounded, and retry it (chosen)
* Fail the whole transaction (`5xx`) so the sender resends it
* Report an error for the PDU in the response and keep nothing
* Retain the PDU in memory only

## Decision Outcome

Chosen option: "retain the PDU durably, bounded, and retry it".

* **Table.** Schema version 23 adds `deferred_pdus` (`event_id` primary key, `room_id`, `origin`, `pdu_json`,
  `received_at_ms`, `attempts`, an index on `room_id`). Main reads and writes it; it is not in the federation worker
  allowlist. Numbers are `TEXT`, like every other numeric column.
* **What is kept.** At the three post-admission `missing_prev_state` returns of `ingest_pdu_event` (references still
  missing after backfill, an unresolvable `auth_event`, a `prev_event` with no state group) the exact envelope that
  would have been stored (`stored_json`, which is the redacted copy after a content-hash mismatch) is written with its
  origin, and the status is the new `PduIngestionStatus::deferred`. A repeat ingest updates the one row and keeps its
  receive time and attempt count. The pending-federated-join queue has its own bounded in-memory queue and is
  unchanged.
* **Bounds, fixed in code (`database::max_deferred_pdu*`).** At most 100 retained PDUs per room, 1000 in total, 16 MiB
  of `pdu_json` in total. A PDU is dropped after 24 hours or after 10 retries that did not place it. When a bound is hit
  the PDU is not retained and the status stays `missing_prev_state`.
* **`/send` result.** `deferred` gets no error entry: the PDU is held, so it is handled. `missing_prev_state` (not
  retained) gets an `error` entry for its event ID, because nothing will retry it and the sender should know. The
  worker-to-main IPC status string carries `deferred` both ways.
* **Retry.** `homeserver::retry_deferred_pdus`, run by a `PeriodicJob` started in `main.cpp` after the dispatcher
  (ADR-0082), re-ingests due PDUs: 30 s back-off doubling to 1 h, at most 32 per call, stop flag checked between
  PDUs, no lock held across the call. The next-attempt time is in memory only, so after a restart every retained PDU is
  due at once. Accepting a PDU wakes the job and makes due the retained PDUs of that room whose JSON names it.
  Expiry is audited as `federation.pdu_deferral_expired`.
* **Signatures.** A row is written only by `ingest_pdu_event`, which is entered after the sender's signature was
  verified (`federation::authorize_federation_pdu` on the same-process path; the worker relay's re-verification,
  ADR-0071). A retry re-enters at `ingest_pdu_event` and does not verify again, which is safe because nothing but that
  function writes the table.

### Positive Consequences

* A PDU the server could not yet place is placed once its history arrives, including after a restart.
* A transaction with one such PDU still succeeds as a whole.
* The sender is told the truth in the one case where nothing will retry.

### Negative Consequences

* The retained set is a new surface a hostile peer can fill. The per-room and total caps bound the memory, and the
  attempts and age limits bound how long a row can sit, but a peer that fills a room's 100 slots keeps the room's
  later unresolvable PDUs from being retained until those expire.
* A retried PDU can be accepted long after it was sent, so a client can see an old event arrive late.

## Pros and Cons of the Options

### Fail the whole transaction

* Good, because the sender retries on its own schedule and we keep nothing.
* Bad, because one PDU we cannot place makes the sender back off from *all* its PDUs for the room (and the
  destination), turning a gap in one room into an outage.
* Bad, because the gap may never fill from the sender's side, so the transaction fails for ever.

### Report an error only

* Good, because it is honest and keeps nothing.
* Bad, because a PDU-level error is not a retry request: servers do not resend a single PDU on it, so the event is lost
  just the same, only now visibly.

### Retain in memory only

* Good, because there is no table to migrate.
* Bad, because a restart loses events the sender was told were handled, and an in-memory queue is bounded by the
  process, not by a schema the operator can inspect.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) (phases B1 and C returned and
  forgot an unresolved PDU)
* Relies on [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md) (relayed PDUs are re-verified before
  ingestion) and [ADR-0082](0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)
  (the retry thread starts after hardening)
