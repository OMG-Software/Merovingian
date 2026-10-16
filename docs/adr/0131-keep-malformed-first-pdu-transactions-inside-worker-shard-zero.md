# Keep malformed-first-PDU transactions inside worker shard zero

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

The EDU-only `/send` fast path inferred that a transaction had no PDUs when the
first PDU yielded no room ID. A malformed first PDU followed by real PDUs could
therefore send the entire transaction into main's request handler (FED-9).
Finding a later room ID looks like a better shard hint, but the proxy's failed
room-sync fallback could then take that transaction into main as well.

## Considered Options

* Bypass only a parsed transaction containing an explicitly empty PDU array;
  retain the empty shard key when the first PDU has no usable room ID.
* Treat missing room IDs as evidence of an EDU-only transaction.
* Search later PDUs for another room ID to select a shard.

## Decision Outcome

Chosen option: "Bypass only an explicitly empty PDU array". Missing, mistyped,
nonempty or unparseable PDU fields do not enable the EDU-only bypass. A malformed
first PDU retains an empty key; the proxy skips its room-sync fallback for that
key and dispatches the transaction through the worker pool, whose empty-key
shard is zero. Later PDUs are not used to choose a different key.

The Matrix v1.19 transaction schema requires the `pdus` array, so a missing field
is not a valid empty-array shorthand. The fast path remains available for actual
empty arrays, and existing media bypass and ordinary room routing are unchanged.

### Positive Consequences

* A malformed first PDU cannot bring later PDUs into main through the EDU-only
  classifier or by selecting a later room's failed-sync fallback.
* Existing EDU-only transaction latency and routing are preserved.

### Negative Consequences

* Transactions without a usable first-PDU room ID use shard zero instead of
  attempting to distribute by a later PDU. Rebalancing needs a separate design
  that preserves the sandbox boundary.
* Main still parses the JSON transaction envelope for classification and shard
  hints. This decision does not move that parsing out of main, remove other
  documented fallback paths, or change worker-disabled deployments.

## Pros and Cons of the Options

### Infer EDU-only from the missing key

Rejected because shard-key absence is not evidence that the transaction has no
persistent events.

### Search later PDUs

Rejected because selecting a later room can invoke the proxy's main-process
failed-sync fallback, undoing the intended malformed-first-PDU boundary.

## Links

* [Architecture](../architecture.md)
* [Matrix v1.19 Server-Server API](../matrix-v1.19-spec/server-server-api.md)
* [29 September 2026 security audit](../security-audit-report-2026-09-29.md)
