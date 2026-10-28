# A room upgrade to version 12 omits predecessor.event_id

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement run 2, `TestMSC4291RoomIDAsHashOfCreateEvent_UpgradedRooms`.

## Context and Problem Statement

`POST /rooms/{roomId}/upgrade` writes a `predecessor` into the new room's create event. v1.19
lets the server choose whether it names the old room's last event:

* the Previous Room `event_id` field "became deprecated and may not be present in all cases. It
  SHOULD still be populated where possible/practical";
* the upgrade's server behaviour says "When upgrading to room version 12 or later, the
  `event_id` property inside `predecessor` MAY be omitted."

This server always populated it. Complement asserts it is absent for a version 12 room. Which
should this server do?

## Decision Drivers

* The spec is the authority; where it allows either, the owner decides (2026-10-27).
* A version 12 room is identified by its create event (MSC4291), so a pointer to the old room's
  last event adds nothing a client needs to find the old room.

## Considered Options

* Omit `predecessor.event_id` when the new room's version has `create_event_is_room_id`
  (version 12 and later); keep it for older versions.
* Always populate it, following the SHOULD, and list the Complement subtest as stricter than
  v1.19.

## Decision Outcome

Chosen option: omit it from version 12 on, because the spec explicitly allows it there and the
field is deprecated. Older target versions keep `event_id`, as the SHOULD asks.
`upgrade_room_options` in `client_server.cpp` keys this on the target version's
`create_event_is_room_id` policy flag.

### Positive Consequences

* Complement's v12 upgrade test passes without a skip-list entry.

### Negative Consequences

* A client that still reads `predecessor.event_id` from a version 12 room finds nothing and must
  look the old room up by its `room_id` and tombstone, as the spec already tells clients to do
  when the field is absent.
