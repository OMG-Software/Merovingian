# A fetched event is recognised as stored by one indexed lookup, and an /event_auth answer is capped by max_auth_chain_ids

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

`verify_and_store_backfilled_event` asks first whether a fetched event is already stored. It did so by walking every row
of the event table under the room stripe and `runtime.mutex`, before any signature check. The `/event_auth` answer of a
state-snapshot recovery has no entry limit (only the 16 MiB response cap), so a remote server in a shared room could make
this server walk its whole event table once per entry until the 45 s backfill deadline (run-3 finding C30).

## Considered Options

* Look the event up by the PDU's `event_id` member in the event table's index, and cap and format-check the answer
* Walk the table less often (once per answer)
* A new configuration key for the `/event_auth` entry limit

## Decision Outcome

Chosen option: "Look the event up by the PDU's `event_id` member in the event table's index, and cap and format-check the
answer". The lookup is `EventTable::find`, followed by the same reference-hash comparison on that one row, so the result
is unchanged. The `/event_auth` answer is refused whole when it holds more than `security.federation.backfill.max_auth_chain_ids`
entries, and an entry that is not a well-formed PDU (`returned_pdu_is_well_formed`: size, canonical JSON, envelope, and no
`event_id` member in a reference-hash room) refuses the answer before anything is looked up.

Why not a new key: an auth chain is what `max_auth_chain_ids` already bounds for `/state_ids`; the `/event_auth` answer is
the same set seen from another endpoint, and a second knob could be set lower than the first and break a recovery the
first allows.

Why not fewer walks: the cost per walk still grows with every room's events, and the attacker chooses the number of
entries. Only an indexed lookup removes the dependence on the table size.
