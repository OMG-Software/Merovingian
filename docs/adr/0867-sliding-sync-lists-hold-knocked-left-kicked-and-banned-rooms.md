# Sliding sync lists hold knocked, left, kicked and banned rooms

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4186 "Lists": the server's list holds the rooms the user is joined to, invited to, "knocked on, left, or been
kicked or banned from". A room the user left of their own accord is listed only if it was "previously sent to the
client in that connection"; a room they were kicked or banned from always is; "Rooms the user has been banned from, but
never joined, should not be part of the list". Such a room is sent its `membership` and, if never joined,
`stripped_state` ("Invite/knock/rejections"). ADR-0864 added invited rooms only, and a rejected or withdrawn invite
left the list.

Nothing after a departure is the user's to read (C-S API "Room history visibility", ADR-0084).

## Decision Drivers

* No event or state after the departure may reach the user: not in the timeline, `required_state`, the name, the
  ranking, the filters or the counts.
* Each such room is reported once per change of membership, as an invite is (ADR-0864), so a long poll is not answered
  with the same room again.
* The extra work is bounded by the user's own membership rows.

## Considered Options

* Keep only joined and invited rooms (ADR-0864).
* List every room the user has any membership row in.
* List them as MSC4186 says, each read only as of the departure.

## Decision Outcome

Chosen option: the third.

* **Which rooms.** `SlidingSyncRequestLookups` keeps the user's `knock`, `leave` and `ban` rows.
  `include_departed_rooms` decides the departed ones before any list is computed: a ban always, unless the user never
  joined (`room_read_access_for` is `none`); a kick (the current member event's sender is another user) always, unless
  the user never joined and the kicker is a user they ignore (as an invite from them is withheld); a leave of their own
  only if the connection was sent the room in any form (`sliding_previously_sent_rooms`: a joined room, an `invite:` or a
  `membership:` entry). A rejected invite that was sent therefore stays, as `leave`, and a withdrawn one (a kick) always
  does.
* **Ranking and filters.** A knocked or departed room's `by_recency` and `bump_stamp` is the membership row's position
  ("when the relevant membership happened"), `by_notification_count` 0. A knocked room's name, type and encryption come
  from its stripped state; a departed room's `by_name` key is empty and it counts as encrypted only if the encryption
  event predates the departure.
* **The response.** Such a room, from a list window only (a subscription still serves joined and invited rooms), is
  sent `initial` with its `membership`. A knock carries the knock's stripped state. A departed room the user never
  joined carries their own member event, stripped. A departed room they were joined to is built by
  `build_departed_room_response`: name, avatar and `required_state` from the state as of the departure, and a timeline
  of the user's own membership events from the departure on, `limited`, with a `prev_batch` for `/messages`. No counts,
  heroes or unread counts.
* **Once per change.** `rooms_seen` records `membership:<room_id>` at the membership row's own stream ordering, never
  the response's visible position: a commit in flight holds that position below rows already stored, and an entry
  recorded there would send the room again on every poll until the commit ends. The room is sent again only when its
  membership row moves past the entry (`sliding_membership_already_sent`). Reporting it drops the room's joined-room
  bookkeeping, so a rejoin is sent with its full snapshot. The entry stays while the membership does, which keeps a
  left room "previously sent"; a join or a forgotten room ends it. An invite the connection was sent that ends with no
  list or subscription to report it (the request asked for none) leaves a `membership:` entry at 0, which no row is at
  or below, so the room stays previously sent and its `leave` is sent once a list holds it again.
* **Waking.** A membership row that is not an invite wakes the poll (any such row may change a list), unless the
  connection was already sent that row as a knock or a departure, by the response's own test
  (`sliding_membership_already_sent`, ADR-0869).

### Positive Consequences

* A client sees a kick or a ban in its room list, and a rejected or withdrawn invite becomes `leave` instead of
  vanishing, as MSC4186 requires.

### Negative Consequences

* A rejected invite stays in the list as `leave` until the client forgets the room or the connection is reset. This
  reverses ADR-0864's "the room leaves the list"; the tests that checked that now check the `leave`.
* `include_departed_rooms` reads the current member event of each departed room per request: bounded by the user's
  rows, not by the store.

## Links

* Extends [ADR-0864](0864-sliding-sync-lists-hold-invited-rooms-as-stripped-state-and-a-new-or-ended-invite-wakes-the-long-poll.md)
* Uses [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md)
* Part of [ADR-0865](0865-sliding-sync-reads-the-msc4186-request-forms-leniently-and-answers-extensions-under-the-names-they-were-asked-by.md)
