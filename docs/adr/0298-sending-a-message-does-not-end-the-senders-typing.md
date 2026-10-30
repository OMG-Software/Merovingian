# Sending a message does not end the sender's typing

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

`PUT /rooms/{id}/send` used to set the sender's typing entry to false, advance the room's typing position and
send a `typing: false` EDU. A conformance test justified it with a quoted "MUST send stop typing events ... if
a user sends a message"; that sentence is not in Matrix v1.19. The Client-Server API, "Typing Notifications",
puts the stop on the client ("When the user stops typing, the state change ... should trigger another HTTP
request"). Complement `TestACLsForEDUs` has a user type, send a message, and then expects the room's
ephemeral section to still carry `m.typing`; with the clear it carried only the receipt. An initial sync omits
an empty `m.typing`, so the room had one event instead of two.

## Decision Outcome

Chosen option: the server never ends a user's typing because of a message. It ends on `typing: false`, on the
timeout, or by the expiry job (ADR-0199). The clear-on-send path, its EDU and its log event
(`room.typing.cleared_on_send`) are removed. The rule that an initial sync omits an empty `m.typing` stays.

Rejected: keeping the clear because a client "obviously" stops typing on send. Clients do send `typing:
false`; a server that second-guesses them also ends typing for a client that sent a message while still
composing the next one.
