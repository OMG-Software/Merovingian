# Shared history visibility orders the join and the event by depth

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestJumpToDateEndpoint/parallel/federation/*`

## Context and Problem Statement

Client-Server API, "History visibility", rule 3: "If `history_visibility` was set to `shared`, and the user
joined the room at any point after the event was sent, allow." `HistoryVisibility` read "after" as "stored
later on this server": the user's newest join had a higher stream ordering than the event. An event fetched
as history (backfill, `/messages`, a remote `timestamp_to_event` answer) is stored after the join it precedes,
so every such event was hidden from a user who joined a `shared` room, and the federated jump-to-date lookups
answered 404. The spec does not say how "after the event was sent" is measured.

## Considered Options

* Compare depth: the user's newest accepted join is deeper than the event
* Walk the room's history back from the user's join until the event is found, within a cap
* Treat every event fetched as history as sent before the join, and keep the stored order for the rest

## Decision Outcome

Chosen option: "Compare depth" (owner decision 2026-10-30). Depth is the event's place in the room's history:
an event is one deeper than the deepest event it builds on, so a join that descends from the event is always
deeper. The check is one comparison per event against a per-request, per-room cached join depth. A walk would
answer exactly but has to be capped and run under `runtime.mutex`, hiding long histories; judging by how an
event arrived would trust the path, not the room's history.

### Positive Consequences

* A user who joined a `shared` room sees the history this server fetches for them.

### Negative Consequences

* Events on parallel branches are ordered only by depth: one of equal depth to the join counts as not before
  it (denied), and a concurrent one of lower depth counts as before it.
* The comparison uses the join's depth for every event in the room. A local join takes this server's next
  depth for the room, but a federated join keeps the depth of the resident's `make_join` template, so the
  resident chooses it, and a high one counts later events of any server as before the join. Such a resident
  already holds those events and could send them to anyone, so this gives it nothing it lacked.

## Links

* Refines [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md)
