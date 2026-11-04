# A number outside Canonical JSON costs one PDU, not the transaction

* Status: accepted
* Date: 2026-11-04

Technical Story: security audit run 2, finding F-83: one PDU holding a float or an out-of-range integer failed
the strict parse of the whole `/send` body, so the X-Matrix signature could not be rebuilt, the request was
refused with 401 or 403 and charged to the peer's bad-signature budget, and every other PDU in it was lost.

## Context and Problem Statement

[ADR-0150](0150-legacy-float-power-levels-are-read-by-the-auth-rules-but-never-hashed.md) keeps hashing strict. Rooms v3 to v5 say servers
"MUST NOT strictly enforce" Canonical JSON and SHOULD handle such JSON where possible, and rooms v6 and later
forbid it. So a v3-v5 event with such a number is legal, and this server knowingly does not handle it. That
was already decided. What was not decided is how much that refusal costs: it took the whole transaction and
counted against the sender as a forged signature.

## Considered Options

* **Authenticate from the numbers as they arrived, and give the PDU its own error (chosen).**
* Refuse the transaction with a clear 400. Rejected: a peer in a v3-v5 room would lose every other PDU in the
  batch, and would retry the same batch for ever.
* Accept such events by hashing the raw bytes. Rejected: this reverses ADR-0150, and the number form is not
  stable through parse and serialize in other implementations, so event IDs and signatures would not be agreed.

## Decision Outcome

`parse_preserving_numbers` keeps a number the canonical parser would refuse as a `RawNumber` holding its exact
bytes. Every other rule of the parser still applies. `serialize_canonical` writes it back verbatim and
`serialize_canonical_strict` refuses it, so it cannot reach anything this server hashes or signs.

`federation_request_payload` and `parse_transaction_body` use it. The signature therefore proves who sent the
bytes, whatever they hold, and a forged signature over such a body is still a 403 charged to the budget, so a
float cannot be used to dodge that budget. In `/send`, a PDU refused only for such a number gets a per-PDU error
in the 200, under the ID its sender would have computed from those bytes. That ID labels the error and is
never stored. It is not counted as a verification failure, because nothing was verified.

An EDU holding such a number is dropped alone in `parse_transaction_body`. Main and the worker share that function,
so no digest is bound and nothing is relayed for it (ADR-0395), and no EDU sink is ever handed such a number.

A body that is not JSON at all answers 400 and is not charged: no signature was checked, so nothing is known
about it.

`origin_server_ts` remains strictly an integer.

### Negative Consequences

* Recorded deviation: rooms/v3.md, v4.md and v5.md say "MUST NOT strictly enforce". An event in those versions
  holding such a number is refused here, and a room relying on one has a gap at that event. ADR-0150 stands.

## Links

* Refines [ADR-0150](0150-legacy-float-power-levels-are-read-by-the-auth-rules-but-never-hashed.md)
* Refines [ADR-0395](0395-bind-worker-edu-relays-to-the-edus-of-the-verified-body-by-digest.md): such a number no
  longer makes both sides refuse the whole body; it drops that EDU on both
