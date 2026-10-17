# Main records every completed federation transaction, whichever process ran it

* Status: accepted
* Date: 2026-10-17

Technical Story: OpenBSD CI, "main key-admission overload survives real worker socket HTTP and
unchanged transaction retry" (failed on PR #509, and 3/3 on PR #510): the retry of an accepted
transaction was processed a second time (EDU redelivered, key resolver called again) after the
proxy fell back to main for the room.

## Context and Problem Statement

Matrix v1.19 (server-server API, PUT `/_matrix/federation/v1/send/{txnId}`) has the sending
server retry the same `txnId` until it receives 200. A retry of a transaction that already
completed must therefore not be processed again: its PDUs are caught by event-ID dedupe, but its
EDUs (typing, receipts, to-device messages) would be delivered twice.

Each process keeps its own bounded dedupe ring (`FederationRuntimeState::accepted_transactions`,
#416). The proxy in main decides per request who runs it: the worker normally; main for EDU-only
transactions; main for a room whose worker reload has failed. When the worker completed a
transaction, only the worker's ring knew it. A retry that then reached main (because the room's
reload had failed) or the worker after a restart was processed as new. The reverse held too: a
transaction main completed during a fallback was unknown to the worker once the room recovered.

Where should completed transactions be recorded so that every route sees them?

## Considered Options

* Main's ring is the record: the proxy records each transaction the worker completes with 200,
  and sends any transaction already in main's ring to main
* Relay main's completions to the worker and the worker's to main over IPC
* Persist completed transactions in the database

## Decision Outcome

Chosen option: main's ring is the record, because every inbound request already passes through
the proxy in main after its signature is verified there, so main sees every completion without a
new IPC frame or table.

* After verifying the X-Matrix signature, `FederationProxy::handle` takes the txnId of a
  `PUT /send/{txnId}` (`federation_send_transaction_id`). If main's ring already holds (origin,
  txnId), it hands the request to main's own handler, which applies its usual rate limit and
  answers the duplicate with 200 and an empty `pdus` map, as it always has.
* When the worker answers a `/send` with 200, the proxy records (origin, txnId) in main's ring
  (`record_completed_federation_transaction`), the same bounded ring main's own handler appends
  to.
* The worker keeps its own ring. It is now a second line, not the record.

The rule for future code: **a new route that can run an inbound `/send` outside main's handler
records its completions in main's ring**, and checks main's ring before running a transaction.

### Positive Consequences

* A retry is answered as a duplicate whether the first attempt ran in the worker or in main, and
  whether or not the room's worker reload has since failed or recovered, or the worker restarted.
* Duplicates in main no longer depend on the worker staying up.

### Negative Consequences

* Main's ring now also holds the worker's transactions, so its configured cap
  (`security.federation.accepted_transaction_cache_entries`, default 50000) covers both.
* The ring is still in memory: a main restart forgets it, as before. Two concurrent sends of
  one txnId can both run before either completes, as before.
* Entries the proxy records carry zero PDU and EDU counts; nothing reads those counts.

## Pros and Cons of the Options

### Relay completions both ways over IPC

* Good, because both rings would stay complete.
* Bad, because it adds a frame type in each direction, and the worker would still decide alone
  whenever an update was lost or delayed.

### Persist completed transactions

* Good, because dedupe would survive a restart.
* Bad, because it adds a write to every inbound transaction, and the read-only worker could not
  record its own completions anyway.

## Links

* [ADR-0162](0162-plan-every-unveil-call-before-making-the-first.md) removes the reason a room's
  worker reload failed on OpenBSD CI, and [ADR-0159](0159-retry-a-false-hot-journal-on-read-only-sqlite-reads.md)
  a SQLite race that can fail one anywhere. This ADR makes any reload failure harmless to dedupe.
