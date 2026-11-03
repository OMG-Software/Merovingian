# Only a transaction writes a peer's trust record

* Status: accepted; refines [ADR-0110](0110-federation-worker-trusts-main-verified-identity.md)
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: finding F-59 of security audit run 2 (a worker's synthetic remote overwrites the trust record, so a
peer can clear its own backoff).

## Context and Problem Statement

ADR-0110 lets a federation worker answer a request main has already verified without resolving the peer: for every
endpoint except `/send`, `send_join`, `send_leave`, `send_knock` and `invite` it builds a synthetic remote with
default trust and skips the worker's trust check. After any 2xx non-transaction answer the handler then set
`consecutive_failures` to zero and copied the whole trust struct over the stored record, so the synthetic defaults
replaced the worker's real record. A peer charged on `/send` could make one cheap read on the same worker and
clear the charge, even while it was already being answered 429, because the synthetic path skips the gate. Main's
record holds none of the worker's charges, so main's gate never stopped it either. On a real record (`send_join`,
`invite` on a worker, or an unverified direct request) the same line reset a sub-threshold count, against the threat
model's rule that only a clean transaction resets it.

## Considered Options

* Skip the write only when the remote is synthetic (carry a flag on the resolution outcome).
* Never let a non-transaction response write trust state.

## Decision Outcome

Chosen option: "Never let a non-transaction response write trust state". Only the transaction path charges a failure
or resets the count, because only a transaction is evidence about the peer's behaviour on the path the backoff
protects. A read, a membership request or an invite that succeeds says nothing about whether the peer's PDUs are
forged. The flag option would leave the real-record reset in place, and trust state must only ever improve from
evidence the peer is responsible for.

The duplicate-transaction path already leaves trust alone for the same reason.

### Negative Consequences

* The backoff is still held per process (main and each shard keep their own record), so a peer can spread traffic
  across shards. That is a separate matter and is not changed here.

## Links

* Refines [ADR-0110](0110-federation-worker-trusts-main-verified-identity.md): the synthetic remote stays, and is
  never written back
* Relates to [ADR-0346](0346-a-relayed-pdu-that-fails-verification-is-not-charged-to-the-relaying-peer.md)
