# A refused upgrade tombstone leaves the replacement room abandoned

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

`POST /rooms/{roomId}/upgrade` runs `create_room` with `runtime.mutex` released, then sends the old room's
tombstone. A power-levels change can land in between, so the tombstone is refused after the replacement room
exists. The replacement room is then orphaned and the client has an error without its ID.

## Considered Options

* Return the replacement room's ID in the error body.
* Accept the orphan as it is.
* Delete the replacement room.
* The upgrading user leaves the replacement room.

## Decision Outcome

Chosen option: "the upgrading user leaves the replacement room". The refusal is logged (`room.upgrade.rejected`,
then `room.upgrade.replacement_abandoned`) with both room IDs, and the tombstone's refusal is returned to the client
unchanged.

* Returning the new room ID in the error body invents a non-spec field and leaves a half-built room for the client
  to clean up.
* Accepting the orphan leaves a room the user is joined to, with a power-levels state they alone control, listed in
  their sync with nothing explaining it.
* Matrix has no room deletion, so leaving is the only way to abandon a room.

If the leave itself fails it is logged at error level; the refusal is still what the client is told.

## Links

* Follows [ADR-0476](0476-a-room-upgrade-moves-aliases-and-closes-the-old-room-after-the-tombstone.md).
