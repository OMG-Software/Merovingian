# An event fetched to fill a gap is checked against the current state

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-16. Refines ADR-0064 phase C and ADR-0070.

## Context and Problem Statement

`verify_and_store_backfilled_event` ran the receipt checks up to the state before the event and then stored it as an
`outlier`. Client read paths withhold only `rejected` and `soft_failed` rows, and an outlier with a state group is judged
visible by the state at the event. A banned user's server could therefore sign a message on a pre-ban branch, send a PDU
naming it, and answer `/get_missing_events` with it: local clients were given a message the same event, sent directly in
`/send`, would have been withheld for.

## Considered Options

* Soft fail a fetched event that fails against current state, keeping its state group
* Make the read paths withhold every outlier
* Exempt events fetched to fill a gap, as history

## Decision Outcome

Chosen: soft fail. `verify_and_store_backfilled_event` authorises an event that passed step 5 against the room's current
state, and one that fails is stored `soft_failed` with its state group. An already stored `outlier` with no state group
that gains one goes through the same check, because the state group is what makes it visible.

An event with no known state-before gets no such check: it has no state group, and nothing shows it to a client.

### Positive Consequences

* Ban evasion through a fetched event is withheld, as the spec and ADR-0064 require.
* Descendants of the event can still be placed and state resolution still sees it ("Soft failed events participate in state
  resolution as normal").

### Negative Consequences

* Honest history fetched after the fact is withheld when its sender can no longer send: a message from a user who has since
  left or been banned, recovered after this server was offline. An event arriving directly in `/send` at that moment is
  treated the same way, so a client sees the same result whichever route the event took.
* The check costs one more walk of the room's current state per fetched event, under `runtime.mutex`, and the recovery budget
  bounds how many there are. `state_entries_for_room` now walks only that room's rows through the state index (ADR-0344).

## Pros and Cons of the Options

### Make the read paths withhold every outlier

A gap filled while a server was briefly offline is ordinary history, and clients are meant to see it. It would also change
every read path instead of one writer.

### Exempt events fetched to fill a gap, as history

Leaves the finding as it is: which events are "history" is chosen by the server sending them.
