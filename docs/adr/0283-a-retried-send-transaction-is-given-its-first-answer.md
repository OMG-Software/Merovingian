# A retried /send transaction is given its first answer, kept within a byte budget

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: PR #545 review (CodeRabbit), follow-up to ADR-0160 and ADR-0280

## Context and Problem Statement

`PUT /_matrix/federation/v1/send/{txnId}` answers 200 with `pdus`, mapping each PDU of the
transaction to its processing result; only an entry with no `error` "can be considered successfully
handled" (Server-Server API v1.19, "Transactions"). A sender retries a transaction under the same ID
until it gets 200, and main's `accepted_transactions` ring makes sure a retry is not processed again
(ADR-0160).

The retry was answered by building `{}` for every PDU it carried. A PDU that failed the first time
(`missing_prev_state`, or an internal error) was then reported as handled, and the sender, which had
lost the first answer, never learned of the failure.

## Considered Options

* Keep each completed transaction's serialized 200 body in its ring entry and replay it.
* Keep only the event IDs that failed, and answer a retry with a generic error for those.
* Process a retry again.

## Decision Outcome

Chosen option: keep the body in `FederationAcceptedTransaction::response_body`, recorded after the
whole answer is built, and replay it to a retry unchanged. `FederationProxy` records the worker's 200
body the same way, so a retry that reaches main gets the worker's answer.

The ring is bounded in kept bytes as well as entries: `FederationRuntimeConfig::accepted_transaction_cache_bytes`
(16 MiB), with the total in `FederationRuntimeState::accepted_transaction_bytes`. Recording evicts the
oldest entries until both bounds hold. An answer larger than the whole budget is not kept, but the
transaction is still recorded, so a retry of it is not processed again and is answered `{}` per PDU,
as before. The budget is fixed, not an operator setting, like `bad_signature_per_ip_rate`.

Keeping only the failed event IDs was rejected: it saves little in the common case (most answers are a
few `{}` entries) and replays a different error text from the first answer. Processing a retry again
was rejected because it delivers EDUs twice and re-runs PDU ingestion (ADR-0160).

### Positive Consequences

* A retry gets the same per-PDU results as the first attempt, errors included.

### Negative Consequences

* Without the byte bound, 50000 entries of 50-PDU answers could hold well over 100 MB. With it, a
  flood of large answers shortens the dedupe window: at 16 MiB, about 6000 maximum-size answers. A
  transaction evicted that way is processed again if retried, as any evicted entry always was.
