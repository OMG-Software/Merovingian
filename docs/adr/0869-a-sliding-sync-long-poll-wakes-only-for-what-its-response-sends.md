# A sliding sync long poll wakes only for what its response sends, and a room is sent again when its summary changes

* Status: accepted
* Date: 2026-11-20

Technical Story: PR #608 review (greptile), comments on account data, receipts, room names, tags and `m.direct`.

## Context and Problem Statement

Full MSC4186 support (ADR-0865) added data a response sends although it predates the request's `pos`: all of a room's
account data when the room enters the `account_data` scope or the extension is turned on (MSC4548), and the user's own
receipts when a room first enters the `receipts` scope (MSC4551). It also made a room's `name` and `avatar` `null` once
removed, and sent a room again when its `is_dm` changed. Three things were missing:

* The long-poll check compared account data and receipts with `pos` only, so a request that would be sent such data
  waited for an unrelated event instead of being answered.
* A response that sent account data on scope entry took no `pos` page, and the receipts block overwrote the flag that
  account data set, so the next request at the same position could read as a retry and be sent the same data again.
* A room whose only change was its name or avatar, or its DM status through `m.direct` alone, was never sent to a
  connection that asked for no timeline and no matching `required_state`; and a change of `m.tag` that moved a room into
  a list filtered on `tags` / `not_tags` did not wake the poll.

## Decision Drivers

* ADR-0863's rule: never wake a poll with a test the response does not share, or it is answered with nothing, again.
* A response that changes connection state with no stream advance needs a new `pos` page (ADR-0862).
* Work under `runtime.mutex` stays bounded by the user's own rows.

## Considered Options

1. Shared floor functions (`account_data_floor_for`, `enters_receipts_scope`) that the builder and the long-poll check
   both call, an OR of every extension's `sent_on_scope_entry`, and `name:` / `avatar:` entries in `rooms_seen` that
   hold the stream ordering of the current `m.room.name` and `m.room.avatar` events the room was last sent with.
2. Wake on any account-data or receipt row of a room in scope, whatever its age; send a room when its name or avatar
   event's ordering is above the room's delta floor.
3. Send `name` and `avatar` only with the timeline or `required_state` that carries their events, as before.

## Decision Outcome

Chosen option: 1.

* The account-data and receipts wake tests read the same floor and first-entry test as `build_extensions`, so a poll
  wakes exactly when the response sends something, and once sent the history moves on and the next poll waits.
* `ExtAccountDataResponse::sent_on_scope_entry` marks a row at or before `pos` sent on entry; every extension ORs into
  `SlidingSyncExtensionResponses::sent_on_scope_entry`, never assigns, and the handler gives such a response a page.
* A room is sent again when the event its name or avatar comes from differs from the one recorded under `name:` or
  `avatar:` (an absent entry is none). Comparing the event, not its ordering against a floor, also catches state
  resolution moving the name back to an older event. `sliding_previously_sent_rooms` strips both prefixes.
* A change of `m.direct` wakes a poll only when it changes the `is_dm` of a joined room the response could send (the
  previous windows and the subscriptions) that the connection has sent, read against its `dm:` entry: the room the
  response sends again. `lists_filter_on_account_data` counts `tags` and `not_tags` as it counts `is_favourite`.

Option 2 wakes a poll for data the response does not send (an old receipt of another user, a room already in scope):
the response is empty and the client polls again at once. Option 3 leaves a removed name on the client for ever, which
MSC4186's `null` exists to prevent.

### Consequences

* Good: no lost wake for anything the response sends, and no wake for anything it does not.
* Good: a renamed or un-named room reaches every connection that holds it.
* Bad: `rooms_seen` holds up to two more entries per sent room. Like the `dm:` entries, they are bounded by the rooms
  the connection was sent, not by the retained-bytes cap, which counts the lists a request makes it keep (ADR-0663).
* A new extension that sends data predating `pos` adds its own floor function, shared with the wake check, and ORs its
  entry flag; a new room summary field the client is told about gets a `rooms_seen` entry the same way.
