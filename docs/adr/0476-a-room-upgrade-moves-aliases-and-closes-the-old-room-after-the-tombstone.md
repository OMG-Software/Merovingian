# A room upgrade moves aliases and closes the old room after the tombstone

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`POST /rooms/{roomId}/upgrade` created the replacement room and sent the tombstone, but left the old room's local
aliases pointing at the tombstoned room and left its members able to send there. The spec's server behaviour list says
"Moves any local aliases to the new room" and, "if possible", lowers the old room's power levels (`events_default` and
`invite` to the greater of 50 and `users_default + 1`).

## Decision Outcome

- Order: replacement room, tombstone, aliases, power levels (the spec lists the aliases before the tombstone). A
  tombstone that is refused fails the upgrade with every alias still on the old room; moving first would leave the
  aliases on a room that was never closed. A failed alias write after the tombstone is a 500 (nothing was
  reported successful that is not).
- Aliases move in one `UPDATE` each (`database::reassign_room_alias`), keeping their creator. The old room's
  `m.room.canonical_alias` is not changed: it names aliases that now resolve to the replacement.
- The power-level change is sent as the upgrader through the ordinary send path, so the auth rules decide whether it
  is "possible". A refusal, or a power-level event holding a value this cannot compute with, is logged
  (`room.upgrade.old_room_power_levels_unchanged`) and the upgrade still succeeds.
- Both values are only raised: a room that already asks for more than the spec's example keeps it.

Rejected: moving aliases before the tombstone, as the spec lists them. Rejected: failing the upgrade when the power
levels cannot be changed; the spec makes the step conditional.
