# Room directory and alias changes need canonical-alias power; aliases record their creator

* Status: accepted
* Date: 2026-10-08

Technical Story: 29 September 2026 security audit, finding CSAZ-12 (missing membership or power checks on
`/report`, `/upgrade`, directory visibility and aliases). The project owner chose the rules below.

## Context and Problem Statement

Any joined member could publish a room in the directory, and any user could create any alias on this
server, `#admin:<server>` included, for any room they had joined; aliases could not be deleted at all. The
spec leaves access control for these endpoints to the server: directory visibility "Servers MAY implement
additional access control checks, for instance, to ensure that a room's visibility can only be changed by
the room creator or a server administrator", and alias deletion "Servers may choose to implement
additional access control checks here, for instance that room aliases can only be deleted by their
creator or a server administrator".

Who may change a room's directory visibility, and create or delete its aliases?

## Considered Options

* **The power to send `m.room.canonical_alias` in the room, or a server administrator; an alias may also
  always be deleted by the user who created it (chosen).**
* The room creator or a server administrator, as the spec's examples suggest. Rejected: it leaves rooms
  whose creator has left, or whose moderators are not the creator, unmanageable.
* Any joined member (the previous behaviour). Rejected: it lets a member squat aliases and advertise a
  room against its moderators' wishes.

## Decision Outcome

Chosen option: canonical-alias power, judged by `homeserver::may_send_state_event`, which compares the
user's effective power level (v12 creators infinite) with `events::required_state_event_power`, the same
function the authorization rules use.

* `PUT /directory/list/room/{roomId}`: a joined user with canonical-alias power, or a server
  administrator; otherwise `403 M_FORBIDDEN`.
* `PUT /directory/room/{roomAlias}`: the alias must follow the appendices' grammar
  (`auth::room_alias_is_valid`) and be on this server's domain, else `400 M_INVALID_PARAM`; then a joined
  user with canonical-alias power, or a server administrator. The creator is stored in
  `room_aliases.creator_user_id` (migration 021).
* `DELETE /directory/room/{roomAlias}`: the alias's creator, a joined user with canonical-alias power in
  its room, or a server administrator; `404 M_NOT_FOUND` when unmapped. Aliases created before migration
  021 have no creator and fall to the other two.
* `POST /rooms/{roomId}/upgrade` is refused with `403` before the replacement room is created unless the
  user may send `m.room.tombstone`, and fails if the tombstone is then refused (a spec 403 condition, not a
  decision, recorded here because the check uses the same helper).
* `POST /rooms/{roomId}/report/{eventId}` answers `404 M_NOT_FOUND` alike for a reporter who is not joined
  and for an event that is not in the room or not visible to them (the spec's 404), and a repeat report of
  the same event by the same reporter writes no second audit row.

**Rule for future code:** a client API gate that stands for a state event the action would send checks
`may_send_state_event` for that event type, not membership alone.

### Negative Consequences

* An appservice or bridge that creates aliases needs canonical-alias power in the room (bridges usually
  create their portal rooms, so they hold it as creators).
* Report de-duplication looks at the newest `server.client_api.max_safety_report_rows` report rows, so a
  report older than that window can be recorded again.
