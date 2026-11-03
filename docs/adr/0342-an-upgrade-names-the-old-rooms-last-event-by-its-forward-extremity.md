# An upgrade names the old room's last event by its forward extremity

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-48.

## Context and Problem Statement

For an upgrade to a room version below 12, `predecessor.event_id` in the new room's `m.room.create`
must be the Event ID of the old room's last known event (ADR-0239). `upgrade_room_options` took it
from `LocalRoom::events.back()`. That vector holds each event's full signed JSON, never its ID, so the
new room's create event carried the old room's last event as a string: a malformed field, a copy of one
event's content visible to everyone in the new room, and a create event that could pass the size limit.

## Decision Outcome

`last_known_event_id` (`client_server.cpp`) returns the ID of the newest, by stream ordering, of the
old room's forward extremities that the event table holds. Forward extremities are accepted events no
accepted event follows, so a rejected or soft-failed event is never named. With none the field is left
out, which the spec allows ("if known"; "SHOULD still be populated where possible/practical").

`LocalRoom::events` is a list of event JSON. Never read an ID from it; take IDs from `EventTable` or
the forward extremities.

## Considered Options

* Parse `"event_id"` out of the last JSON string. Rejected: the stored vector is a cache of room
  history in an order that membership paths also touch (`std::ranges::replace` on a cosigned invite), and
  an extremity is the definition the spec's "last known event" and the DAG use.
* Newest row of the room by stream ordering. Rejected as the primary source: it needs a walk of the
  event table, and can name a rejected event.

## Links

* Refines [ADR-0239](0239-a-room-upgrade-to-version-12-omits-predecessor-event-id.md)
* Related to [ADR-0318](0318-a-membership-template-offers-the-rooms-stored-forward-extremities.md)
