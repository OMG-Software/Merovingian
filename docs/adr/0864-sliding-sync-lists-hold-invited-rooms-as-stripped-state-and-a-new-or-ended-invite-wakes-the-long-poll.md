# Sliding sync lists hold invited rooms as stripped state, and a new or ended invite wakes the long poll

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

A user invited by a local user (`/createRoom` with `invite`, or `POST /invite`) never saw the invite in MSC4186
simplified sliding sync: the Persephone client, which sends one unfiltered list and no room subscriptions, showed
nothing. Two things combined:

* `compute_room_list` started from the user's joined rooms only. The invites `SlidingSyncRequestLookups` read were used
  by the `is_invite` filter alone, so an unfiltered list left them out and `is_invite: true` matched nothing. Only an
  explicit `room_subscriptions` entry reached the stripped-state path.
* The long-poll relevance check ([ADR-0609](0609-sliding-sync-decides-a-long-poll-wake-from-the-callers-own-rooms.md))
  counts an event only in a room the user has joined. The invite event is in a room the user has not joined, so the
  poll parked again on every wake until its timeout.

MSC4186 says an unfiltered list holds the rooms the user is invited to, `is_invite` selects them, and an invited room is
sent `invite_state` (stripped state) and nothing else. The C-S API ("Room history visibility") still forbids sending a
user only invited to a room any of its events.

## Decision Drivers

* An invited user must never get a timeline or `required_state` of the room, through any list or subscription (CSAZ-1).
* The ADR-0609 rule stays: an event in a room the user is not in does not wake a poll. Only the user's own membership
  rows may.
* One answer to "may this invite be shown now" for the wake, the lists and the subscriptions; a poll woken for an
  invite it then withholds is answered with nothing, and the client re-polls at once.
* Work per request under `runtime.mutex` stays bounded by the user's own rows, not by the size of the store.

## Considered Options

* Serve invites through `room_subscriptions` only (the old behaviour).
* Put deliverable invites in every list's candidate set as stripped-state rooms, and wake the poll for the user's own
  invite rows (new) and for the end of an invite the connection was sent.
* As the second, and serve a rejected or withdrawn invite as a left room with its leave event in the timeline, as
  Synapse does for newly left rooms.

## Decision Outcome

Chosen option: the second.

* **Which invites.** `sliding_invite_is_deliverable` (`ClientServerRuntime.cpp`) is the one test, used by the wake
  check, the lists and the subscriptions. It withholds an invite whose inviter the user ignores and an invite the room's
  held state does not yet have (ADR-0301), and the whole set while the user blocks invites (ADR-0552). It reads the
  invite record and two current-state rows by index (`find_invite_row`, `find_current_state_event_id`); it never builds
  `InviteRoomStateIndex`, which scans the whole state table, since a long poll reruns on every wake.
* **Lists.** `SlidingSyncRequestLookups` keeps the user's invite rows with their stream orderings, and the handler
  withholds the undeliverable ones (`withhold_invite`) before any list is computed. `compute_room_list` ranks the joined
  rooms and the deliverable invites together. For an invited room: `by_recency` is the invite row's stream ordering (the
  bump stamp; the same allocator as event orderings, so the two compare), `by_notification_count` is 0, and
  `by_name`, `room_types` and `is_encrypted` read the invite's stripped state, never the room's current state, which
  the user may not read.
* **The response.** A windowed room the lookups call invited is never passed to `build_room_response`: it joins the
  subscription invites and is sent `initial` with `invite_state` only. `rooms_seen` records it as `invite:<room_id>`
  with the response's position, and it is sent again only when the invite row's stream ordering passes that, that is,
  for a new invite. Reporting an invite drops the room's joined-room bookkeeping on the connection (`rooms_seen`,
  `lazy_members_sent`, `room_timeline_limits`), so an accepted invite is sent as a new room with its full snapshot.
  An `invite:` entry whose room is no longer an invite of the user is dropped.
* **The wake.** With lists or subscriptions requested, the check reads the user's own membership rows (already read for
  the joined set) and answers the poll when:
  * an invite row is newer than `since`, is deliverable, and a list without `is_invite: false` or a subscription could
    hold it; or
  * a row newer than `since` is not an invite for a room the connection has an `invite:` entry for: the invite was
    rejected, withdrawn or accepted.
  Every other row and every event in a room the user is not in still parks the poll.

### Positive Consequences

* A local invite reaches a waiting sliding sync client within one wake, by either path that makes one.
* Clients that list rooms (Element X, Persephone) show invites without subscribing to rooms they cannot know about.
* An invite is sent once per connection, and again only for a new invite.

### Negative Consequences

* A rejected or withdrawn invite is visible only as the list's changed `count` and window (its `ops`); no room entry
  says the invite ended. A client that ignores list ops learns it when it acts on the room.
* A change of a room's name after the invite does not reach the invitee until they join: `invite_state` is the
  snapshot the invite carried.

## Pros and Cons of the Options

### Serve a rejected or withdrawn invite as a left room with its leave event

* Good, because a client that reads only `rooms` sees the invite end.
* Bad, because it builds a room response for a room the user never joined: the timeline and `required_state` code
  would have to prove, for every option and extension, that nothing but the user's own leave is sent. One mistake there
  leaks the room. Not taken.

## Links

* Refines [ADR-0609](0609-sliding-sync-decides-a-long-poll-wake-from-the-callers-own-rooms.md) (the relevance check)
  and [ADR-0665](0665-a-sliding-sync-request-learns-the-callers-rooms-once-and-every-list-reads-that.md) (the lookups)
* Relates to [ADR-0301](0301-held-room-state-is-current-only-while-a-local-user-is-joined.md) and
  [ADR-0552](0552-invite-permission-is-decided-where-account-data-is-held-and-createroom-drops-only-a-remote-block.md)
