# A room entering the typing or receipts scope is sent what it lacks

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

[ADR-0861](0861-the-typing-and-receipts-extensions-follow-msc4508-scope-and-wake-a-long-poll-only-within-it.md) made
the sliding sync `typing` and `receipts` extensions serve the joined rooms of their MSC4508 scope, but both still sent a
room only what changed after the request's `pos`. A room's place in the scope moves with the request's `lists` and
`rooms` keys and with the list windows, so a room can enter the scope holding state the connection was never sent:

* bob starts typing in a room outside the typing scope; a later response moves `pos` past it; the client then adds the
  room to the scope. The room's typing position is older than `pos`, so bob was never reported, however long he typed.
* a room drops out of the receipts scope, a receipt there changes, a response moves `pos` past it, and the room comes
  back. The receipt is older than `pos`, so the client kept the stale one until it changed again.

MSC4508 requires both: "Whenever a room enters scope on a connection, the server MUST send the room's current typing
state", and a room that drops out of scope and re-enters it must end up with up-to-date state. MSC4551 spells the
receipts case out: the receipts that changed after the `pos` of the first request in which the room was out of scope.

## Decision Drivers

* MSC4508's entry and re-entry rules.
* A long poll must never be answered twice with the same content: an answer that sends nothing, or that the next
  request cannot acknowledge, is followed by an instant re-poll (the spin ADR-0855 and ADR-0862 guard against).
* The connection state stays bounded by the user's rooms, never by what a client sends.

## Considered Options

* Keep sending changes after `pos` only, and leave entry to the client.
* Send a room's whole receipt set and typing state every time it is in a response.
* Keep, per connection, what each response left in each scope, and send a room entering the typing scope its current
  typing state and a room back in the receipts scope the receipts that changed since it dropped out.

## Decision Outcome

Chosen option: the third.

* `sync::ExtensionScopeHistory` holds the joined rooms of the typing scope, the joined rooms of the receipts scope, and,
  for each joined room that dropped out of the receipts scope, the sync stream position after which it was sent no
  receipt (its floor). The connection keeps it as `extension_scope_history`, inside the pending response like every
  other connection state, so a retried `pos` is answered from the committed history and the same content.
* The handler hands `build_extensions` the committed history through `ExtensionScopeSource::history`. A room in the
  typing scope that the history does not hold enters it (`sync::enters_typing_scope`) and is reported with its current
  typing list whatever its typing position, left out when nobody it would be sent is typing. A room in the receipts
  scope is read from `sync::receipt_floor_for`: its floor when it comes back, else the request's position.
* A room that leaves the receipts scope drops out at the request's position. A room that was out keeps its floor, a
  room back in scope gives it up, and a room the user is no longer joined to keeps none: on rejoining it enters afresh,
  as MSC4551 asks. A request without the extension leaves its scope empty, so enabling it again starts afresh.
* The long-poll check reads the same two functions: a room entering the typing scope wakes the poll while someone the
  user has not ignored is typing there, and a receipt counts above the room's floor, from a sender not ignored. A wake
  is answered only with something the response sends.
* What a room entering the scope is sent moves no stream, so the response's token can equal the request's. Such a
  response (`SlidingSyncExtensionResponses::sent_on_scope_entry`) takes the request's page plus one, as a sticky
  delivery does (ADR-0862), so the next request acknowledges it and commits the history.
* A room entering the receipts scope for the first time is sent the receipts after the request's position, as before.
  MSC4551's "initial receipts" belong to its `org.matrix.msc4551.receipts` key, which this server does not implement;
  the `receipts` key keeps its existing behaviour on that point.

### Positive Consequences

* A client that widens the typing scope sees who is typing there at once, without waiting for the next change.
* A room scrolled out of a list and back gets the receipts it missed, so read markers are not left stale.

### Negative Consequences

* A connection keeps a set of room IDs per extension and a floor per room that left the receipts scope, all rooms the
  user has joined: bounded by the user's rooms, like `rooms_seen`, not counted against the per-device byte budget,
  which bounds what a request makes a connection keep.
* A room that comes back after a long time can be sent many receipts at once, at most one per user, receipt type and
  thread, the same bound as the room's whole receipt set.

## Links

* Extends [ADR-0861](0861-the-typing-and-receipts-extensions-follow-msc4508-scope-and-wake-a-long-poll-only-within-it.md)
* Relates to [ADR-0862](0862-a-sliding-sync-pos-carries-a-page-and-sticky-delivery-keeps-redactions-withheld-refreshes-trimmed-rooms-and-loads-sticky-senders.md) (the `pos` page) and
  [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md) (sticky events entering scope)
