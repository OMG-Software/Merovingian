# A sender's member event is looked up by key, never by scanning the room's state

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

An incremental sync that is not limited sends no state today, yet lazy-loading must add the members of the timeline senders
as they were at the start of the timeline. `/sync` runs under `homeserver.mutex`, and ADR-0435 and ADR-0436 removed whole
table scans from it.

## Decision Outcome

`member_event_at_timeline_start` asks the current state index (`find_current_state_event_id`, a hash lookup) and the event
table (a hash lookup). If the current member event is older than the first timeline event it is the one in force. Otherwise
(the sender's membership changed at or after the timeline began) it walks the state group chain of the first event once with
`sync::lookup_state_in_group` (shared with `HistoryVisibility`), reading the chain's rows, not the room's. When the chain is
unreadable, the current member event stands in: sending too many is valid, omitting one is not. A room with nothing to
deliver does no lookup. `compute_state_before` is not used: it reads the whole state and may resolve it.
