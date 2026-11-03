# A relayed PDU that fails verification is not charged to the relaying peer

* Status: accepted; supersedes the relayed-PDU part of [ADR-0081](0081-failed-inbound-signatures-are-never-charged-to-the-claimed-origin.md) and the failed-lookup penalty of [ADR-0133](0133-preserve-local-key-admission-denial-separately-from-remote-failure.md)
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: finding F-22 of security audit run 2 (a third server pushes an honest relaying peer into the
five-minute inbound backoff).

## Context and Problem Statement

A `/send` transaction is authenticated as the X-Matrix origin, but its PDUs may be authored by other servers: the
spec has a resident server send an accepted `send_join` or `send_leave` event on "to other servers participating in
the room", so a relay's transaction legitimately carries a third server's PDUs. Until now a PDU that failed
verification charged `consecutive_failures` on the transport peer whatever its sender domain was, and ADR-0081
justified that with "which the peer's own key caused". That holds only when the sender's domain is the origin.

For a relayed PDU the outcome depends on the sender server's key material and availability. That server controls
both: it can serve the relay a good key and this server an error or a different key. Three such PDUs put the honest
relay into the 429 'remote backoff required' state for five minutes on one worker shard, refusing its `/send`,
`send_join`, `send_leave`, `send_knock` and `invite`.

## Decision Drivers

* A peer's trust record must fall only on evidence the peer is responsible for.
* The spec answers a failed PDU inside a 200 response with a per-PDU error; it does not ask for the relay to be
  punished.
* The cost of a relay that sends many bad third-party PDUs is already bounded by other limits.

## Considered Options

* Keep charging every failed PDU to the transport peer (the status quo).
* Exempt every failed key lookup from trust accounting (the option ADR-0133 declined).
* Charge a failed PDU to the transport peer only when the PDU's sender domain is the X-Matrix origin.

## Decision Outcome

Chosen option: "Charge a failed PDU to the transport peer only when its sender domain is the X-Matrix origin",
because it keeps the penalty exactly where the peer is the author and removes it where a third server decides the
outcome.

* A relayed third-party PDU that fails verification is dropped with its per-PDU error and is not counted against the
  relay. Cost control for a bad relay stays with the per-origin transaction and PDU rate limits and the
  key-resolution budgets (`key_resolution_per_ip_rate`, `key_resolution_max_in_flight`, the failure cache).
* A PDU whose sender domain cannot be read is charged. A well-formed event always has one, so such a PDU cannot be a
  faithful relay of a valid event; the transport peer is its author for the purposes of trust.
* The other charge sites on the `/send` path are unchanged: a body that does not parse, a transaction whose `origin`
  differs from the request origin, and a transaction over the size or PDU/EDU limits are all the peer's own
  transaction.
* A transaction in which any PDU failed verification, charged or not, does not reset the failure count. A clean
  transaction is the evidence of good behaviour that resets it, and one carrying a failed PDU is not that evidence;
  without this rule a peer could reset its own count by adding a relayed PDU that fails to a transaction.

### Negative Consequences

* A hostile peer can claim a third server as the sender of a forged PDU and so avoid the charge for it. The forged
  PDU is still refused, and the peer is still bounded by the rate limits and key-resolution budgets, which are what
  limit the cost of such a stream. The backoff was never the only bound.

## Links

* Supersedes the relayed-PDU wording of [ADR-0081](0081-failed-inbound-signatures-are-never-charged-to-the-claimed-origin.md)
  ("forged relayed PDUs ... which the peer's own key caused") and the penalty ADR-0133 kept for a failed relayed lookup
* Relates to [ADR-0347](0347-only-a-transaction-writes-a-peers-trust-record.md)
