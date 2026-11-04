# Bind worker EDU relays to the EDUs of the verified body by digest

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, F-74 (refines [ADR-0142](0142-bind-worker-edu-relays-to-live-main-verified-requests.md))

## Context and Problem Statement

ADR-0142 made main admit a worker's `edu_ingest` frame only under a live pending request whose
main-verified origin equals the frame's claimed origin. That proves the frame names a server main
authenticated, not that the EDU was in anything that server sent. `edu_type` and `content_json` come from
the worker and were never compared with the signed body, and one parent could be used any number of times,
so a compromised worker holding any live verified request from server X (the worker chooses when to answer,
so it can hold one open until the deadline) could inject plaintext to-device messages, receipts, typing and
presence attributed to X's users. Relayed PDUs do not have this gap: main re-verifies their signatures. An EDU
has no signature of its own; its authenticity is that it was in a request body carrying X's X-Matrix signature,
which main verified and holds.

How does main know a relayed EDU was in the body it authenticated, without taking over the parsing of untrusted
EDUs?

## Decision Drivers

* The worker is assumed compromisable; main must not act on its content without a check main can make itself.
* The worker is the process that parses untrusted EDU JSON today; keep that exposure there.
* An honest relay must never be refused: the worker's frame must match what main computes from the body.
* The check runs on the IPC dispatch thread under `runtime.mutex`; it must be small and bounded by the request.
* No libsodium outside `src/crypto/` (`src/ipc/AGENTS.md`).

## Considered Options

* Main processes the EDUs of the verified `/send` body itself and the worker relays none.
* Main keeps the whole parsed EDU list per pending request and compares the relayed EDU to it.
* Main keeps a digest of each canonical `(edu_type, content)` pair per pending request; a relay must match an
  unused digest, which it consumes.
* Sign the relay: have the worker authenticate EDUs with a key.

## Decision Outcome

Chosen option: "digest of each canonical `(edu_type, content)` pair, consumed on match", because it closes the
gap with the smallest main-side check and leaves the EDU parsing and routing in the worker.

* `WorkerPool::handle` calls `verified_send_edu_digests` for a signature-verified `PUT .../send/{txnId}`. It runs
  `federation::extract_transaction_edus` on the body main holds, which is the same parse
  (`canonicaljson::parse_lossless`), the same members skipped and the same canonical serialisation that
  `handle_inbound_federation_request` applies before it calls `edu_sink`. The digest of each pair is
  `federation::edu_relay_digest` (`crypto::generic_hash` over the length-prefixed type and the content), so
  libsodium stays in `src/crypto/`. The digests go to `IpcChannel::send_request`, which moves them into the
  `PendingEntry` before the entry is published.
* `handle_edu_ingest_request` hashes the relayed `(edu_type, content_json)` before taking `runtime.mutex`, then
  calls `IpcChannel::consume_pending_edu`, which under `pending_mu_` re-applies the ADR-0142 checks (live, healthy,
  not ready, before the deadline, exact origin) and marks the first equal unused digest used. A relay with no
  such digest is refused with `rejected_invalid`, logged at warning level, and does not reach `edu_sink`.
  The pending lock covers a scan of at most the transaction's EDU limit and never a sink call or network call.
* The digests are one per occurrence, so an EDU the body carried twice may be relayed twice and no more. They
  are bounded by `security.federation.max_transaction_edus`: a body over it gets no digests, because the worker
  refuses such a transaction whole and relays none of it.
* Any other verified request, an unverified one, a body that is not a valid transaction, or one the lossless
  parse refuses gets no digests, so nothing can be relayed under it.
* Honest relays match because the worker relays exactly the content string it parsed with the same function:
  key order and whitespace are canonicalised before both digests; a duplicate key or an over-deep or
  over-large body makes the parse fail on both sides, so the worker answers 400 and relays nothing while main
  binds nothing. An EDU holding a float or an integer outside the canonical range is dropped alone on both
  sides ([ADR-0398](0398-a-number-outside-canonical-json-costs-one-pdu-not-the-transaction.md)).

### Positive Consequences

* A compromised worker can relay only EDUs that a server it holds a live verified request from actually sent in
  that request, and each at most as many times as it was sent.
* The EDU parser and sink routing stay in the worker; main adds one hash and one bounded scan per relay.

### Negative Consequences

* A relay is byte-exact against `extract_transaction_edus`; a future change to how the worker canonicalises
  content must change that one function, not a copy. `WorkerEventLoop` must keep relaying the string it received
  from `parse_inbound_edu_envelope`.
* A compromised worker can still replay or reorder, within one request, EDUs that really were sent, and can
  choose when. Cross-request replay is bounded by the existing idempotence windows.
* Main parses the transaction body once more for every verified `/send` on a worker shard.

## Pros and Cons of the Options

### Main processes the EDUs itself

The audit's alternative: drop the worker EDU relay and have main run the EDUs of the verified body.

* Good, because no relay channel remains to forge.
* Bad, because it moves the parse and dispatch of untrusted remote EDU content (to-device fan-out, device-list
  and typing handling) into the main process, which the worker exists to keep out; an EDU-parsing defect would
  then be in main.
* Bad, because the worker already owns the ACL, rate-limit and per-EDU drop handling around the sink; main would
  have to reproduce them in step, or EDUs in a transaction the worker answered would be handled twice.
* Bad, because the worker's transaction answer and main's EDU processing would be two views of one transaction.

### Keep the parsed EDU list

* Good, because it would allow a field-level comparison.
* Bad, because it holds up to the transaction's whole EDU content per pending request for the length of the
  request, where a digest holds 64 hex characters per EDU.

### Digest, consumed on match

* Good, because the check is small, bounded and independent of EDU type.
* Good, because "once per occurrence" falls out of the consume step.
* Bad, because it needs the worker and main to canonicalise identically; one shared function guarantees that.

### Sign the relay

* Bad, because the worker holds no key by design (ADR-0078), and a key it held would be stolen with the worker.

## Links

* Refines [ADR-0142](0142-bind-worker-edu-relays-to-live-main-verified-requests.md), which recorded this as a residual
* Related [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
