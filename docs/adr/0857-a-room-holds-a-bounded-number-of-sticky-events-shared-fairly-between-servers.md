# A room holds a bounded number of sticky events, shared fairly between servers

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

[ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md) caps each
sender at `server.sticky_events.max_per_sender` unexpired sticky events. A room has no cap, so many senders together
can fill one room: a remote server can register as many users as it likes and give each the per-sender cap. Every
classic `/sync` of every member then carries the whole set, and a client asked for MatrixRTC call memberships (the
reason sticky events exist) has to read through the flood to find them. MSC4354 suggests a cap of 100 on the classic
`/sync` section and has no per-room limit. How is a room bounded, and what goes when it is full?

## Decision Drivers

* A flooding server must not be able to push real call memberships out of a room. Sticky events are what a client reads
  to learn who is in a call; losing them breaks the call for an hour.
* Storage and every `/sync` must be bounded per room whatever the number of senders.
* Recording an event must never be refused for the cap: the event itself is already stored and federated. Only its
  sticky row is at stake.

## Considered Options

* Refuse the new row once the room is at the cap.
* Expire the room's oldest row, whoever sent it.
* A per-server count cap on top of the per-sender cap.
* Expire the oldest row of the server holding the most rows in the room (fair share).
* A sticky cursor in the stream token, so classic `/sync` can page through an uncapped section.

## Decision Outcome

Chosen option: "Expire the oldest row of the server holding the most rows in the room", because it is the only one
under which a flooding server displaces nobody but itself.

* `server.sticky_events.max_per_room` (default 1000, 1 to 10,000, restart required) bounds a room's unexpired rows.
* `database::record_sticky_event` takes both caps (`StickyEventCaps`). It first expires the sender's oldest rows past
  `max_per_sender`, then, while the room would hold more than `max_per_room`, expires the oldest row, by (expiry,
  event ID), of the server whose users hold the most rows in the room. A tie goes against the new row's own server when
  it is tied for most, otherwise the smallest server name, so the choice is deterministic. The new row takes part: when
  it is the one chosen it is not stored and the other rows stay. All of it is one transaction.
* A row whose expiry is at or before now is a successful no-op before anything else is judged, so a negative or past
  `origin_server_ts` stores nothing.
* The room cap is what bounds a classic `/sync` section, which carries every chosen event: classic `/sync` has no
  cursor, so an event left out would never be sent ([ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)). Sliding sync keeps its `limit` and
  its per-connection record of what was delivered ([ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)),
  which the room cap now bounds too.

### Positive Consequences

* With `n` servers holding rows, each keeps at least `max_per_room / n` of them however hard another floods.
* A room's table rows, its classic `/sync` section and a sliding-sync connection's `sticky_delivered` for it are all
  bounded.

### Negative Consequences

* Within one server the oldest row goes, so a server with many genuine users in a full room loses its own oldest call
  memberships first. Those are the ones nearest expiry.
* Recording walks the room's unexpired rows when the room is over the cap: at most `max_per_room` plus one.

## Pros and Cons of the Options

### Refuse the new row once the room is at the cap

* Good, because nothing already held changes.
* Bad, because a server that fills a room first locks every later call membership out for an hour.

### Expire the room's oldest row, whoever sent it

* Good, because it is simple.
* Bad, because a flooding server's newer rows push out everyone else's, which is the attack.

### A per-server count cap on top of the per-sender cap

* Good, because one server's share is fixed.
* Bad, because a fixed share is either too small for a large genuine server or too large to stop a flood, and the room
  still fills from many servers.

### A sticky cursor in the stream token

* Good, because classic `/sync` could deliver an uncapped section in pages.
* Bad, because it changes the token every client holds, for a section the room cap already bounds; ADR-0855 rejected it.

## Links

* Refines [ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)
* Amends [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)
* Amended by [ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)
