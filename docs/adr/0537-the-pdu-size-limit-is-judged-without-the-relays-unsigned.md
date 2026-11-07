# The 64 KiB PDU limit is judged without the relay's unsigned

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

`parse_inbound_pdu_envelope` and `pdu_format_violation` applied the 65 536 byte event limit to the PDU as received,
`unsigned` included. `unsigned` is covered by no signature or hash and is removed before anything is stored
(ADR-0402), so a relay could make a legal event unreadable by attaching a large `unsigned`. The spec limit is on the
event as signed.

## Decision Outcome

`pdu_format_violation` serialises `events::without_unsigned(event)` before the size check. The raw-byte check in
`parse_inbound_pdu_envelope` stays only as a work bound before parsing, at `max_raw_pdu_bytes` (four times the
limit), so a hostile body is never parsed at any size and a relay keeps room for its own `unsigned`.

### Consequences

* A PDU of exactly 64 KiB with a large `unsigned` is accepted; one byte over without it is refused.
* Do not move the size check before the strip, and do not tighten the raw bound to the event limit.

## Links

* Refines [ADR-0402](0402-unsigned-is-built-from-what-the-server-computes-never-stored-from-a-remote-pdu.md)
