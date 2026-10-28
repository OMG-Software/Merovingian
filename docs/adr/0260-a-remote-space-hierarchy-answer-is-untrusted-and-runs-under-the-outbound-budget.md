# A remote space hierarchy answer is untrusted and runs under the outbound budget

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (D20)

## Context and Problem Statement

The client hierarchy now asks other servers (`GET /_matrix/federation/v1/hierarchy/{roomId}`) for child rooms it holds no state for, and our federation hierarchy must decide what to show a requesting server. Both cross a privacy boundary.

## Considered Options

* Treat the remote answer as untrusted and filter per user; one outbound slot per walk; serve a restricted room to a server only while one of its users is joined to an allowed room
* Pass the remote chunk through
* Take an outbound slot per room

## Decision Outcome

Chosen option: "Treat the remote answer as untrusted and filter per user; one outbound slot per walk; serve a restricted room to a server only while one of its users is joined to an allowed room", because a remote server could otherwise forge or leak rooms. Only the requested room's answer is accepted, only children the space's own `children_state` names are taken, only spec fields are copied, local state wins, and each room is shown only if the user may see it by the summary's `join_rule`, `world_readable` and `allowed_room_ids`. The walk takes one ADR-0079 slot at its first remote call and holds it (the per-client cap is 1, so a slot per room would refuse the walk's second remote room), with one 10 s deadline, at most 16 calls and 3 servers per room; a refused slot answers 429. Inbound, the spec's "could feasibly peek/join" is read as join eligibility, and known but unviewable children go in `inaccessible_children`. `suggested_only` also narrows each space's `children_state`.

### Positive Consequences

* Federated spaces show remote children without trusting the remote server.

### Negative Consequences

* Every page repeats the remote calls (no cache).

## Links

* Relates to [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
