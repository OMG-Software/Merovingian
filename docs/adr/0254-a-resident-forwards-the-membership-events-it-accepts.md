# A resident forwards the membership events it accepts

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A1)

## Context and Problem Statement

When this server is the resident and accepts another server's `send_join`, `send_leave` or `send_knock`, it stored the event and answered, but never sent it to the room's other servers, so a third server never learnt of the join and sent the user nothing. The spec requires the forwarding (Server-Server API, Joining Rooms: "The resident server must also send the event to other servers in the room"); where it is done, and what is forwarded, is ours to decide.

## Considered Options

* Forward from main, through the same queueing function as locally composed events
* Forward from the federation worker that accepted the request
* Forward every received copy, soft-failed and rejected included

## Decision Outcome

Chosen option: "Forward from main, through the same queueing function as locally composed events", because only main has the signing key and the dispatch worker, and one function (`queue_event_to_room_servers` in `room_service.cpp`) means the two paths cannot drift. The membership acceptor calls `federate_accepted_membership_event` after an accept, with runtime.mutex already held; it only enqueues. The stored copy is sent (for a restricted join it carries our co-signature) to every server with a joined member after the event applies, except this server and the server that sent the request. A rejected or soft-failed event is sent to no one: a soft-failed event must not become anyone's prev event.

### Positive Consequences

* A third server learns of a join, leave or knock accepted here.

### Negative Consequences

* A new acceptance path must call the same function, or the gap returns.
* Servers whose only members are invited are not sent the event.
