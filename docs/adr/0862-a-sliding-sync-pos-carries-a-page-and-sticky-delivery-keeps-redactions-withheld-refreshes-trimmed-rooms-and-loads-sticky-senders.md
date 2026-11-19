# A sliding sync pos carries a page, and sticky delivery keeps redactions withheld, refreshes trimmed rooms and loads sticky senders

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

A review of the sticky events change
([ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md) to
[ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md))
found four places where it was wrong:

* **A sliding sync backlog stalled.** A room with more undelivered sticky events than the request's `limit` is sent
  over several responses. When no stream advanced, a response's `pos` equalled its request's. The next request at
  that `pos` then read as a retry of the request, not an acknowledgement of the response
  (`requested_pos != pending.request_pos`), so the connection never committed the events it had sent, and every later
  request was answered with the same page. Events past the first page were never delivered.
* **An unapplied redaction was sent as a sticky event.** `sticky_candidates_of_room` took every accepted event with an
  unexpired row. An `m.room.redaction` whose target the server has not received is withheld from every client
  (rooms/v3.md "Handling redactions"); `HistoryVisibility::can_see` withholds it, but the sticky section did not ask.
* **The federation worker served rows the sender cap had removed.** Recording a sticky event past
  `max_sticky_events_per_sender` removes that sender's oldest rows, which can be in other rooms. Only the new row's room
  was reported changed, so the worker's snapshots of the other rooms still held the removed rows and kept serving those
  events past history visibility until something else rebuilt the room.
* **A lazy-loading classic `/sync` sent a sticky sender's member from the wrong place.** The member of a sender whose
  only delivered events were sticky was read at the oldest sticky event. That event can sit before the timeline's
  start, and a sender who joined after the timeline's start had no member there at all, so the client was sent no
  member for an event it was sent.

## Decision Drivers

* A sliding sync retry must be answered with the same response, as every other connection state is (ADR-0221).
* `StreamToken` and classic `/sync` tokens stay as they are: ADR-0855 rejected a sticky component.
* A token is unauthenticated input and never moves server-wide state.
* The sticky exemption is from history visibility only (MSC4354); it is not a way past other withholding rules.
* The database layer does not know about the runtime or the worker.

## Considered Options

For the backlog:

* A page number after the stream token in a sliding sync `pos` only.
* A sticky component in `StreamToken`.
* A fresh random nonce in every response's `pos`.
* Allocating a sync stream ID when a response delivers sticky events, so the position moves.

For the other three: the record call returns the rooms other than its own that lost a row, and the caller tells the
worker; sticky candidates ask `redaction_is_withheld`; a sticky-only sender's member is the one at the timeline's start
when that state holds one, else the one as of the response.

## Decision Outcome

Chosen options:

* **A sliding sync `pos` is a `SlidingSyncPos`**: a stream token and, when not 0, `.<page>` after it
  (`SlidingSyncPos.hpp`). A response that delivers sticky events while no stream advanced (its token equals the
  request's) carries the request's page plus one; any other response has page 0. The page names a response and says
  nothing about the streams: every stream comparison reads the token alone. A retry carries the old page and is
  answered from the committed state with the same events and the same `pos`. The page is read strictly (1 to 20
  digits, no leading zero, fits 64 bits) so one position has one spelling. Classic `/sync` tokens never carry a page.
* **`sticky_candidates_of_room` skips a redaction that has not been applied** (`database::redaction_is_withheld`),
  as `HistoryVisibility::can_see` does.
* **`record_sticky_event` returns a `StickyEventRecordOutcome`**: whether it succeeded, and `other_rooms`, each room
  other than the row's own that lost a row to the sender cap, once. The room cap only takes rows of the row's own
  room. The send path and the federation path call `notify_room_changed` for each, so the worker rebuilds those
  snapshots.
* **A sticky-only sender's member** (a sender of a delivered sticky event and of no delivered timeline event) is the
  member at the timeline's start when the state there holds one; otherwise, and when the timeline is empty, it is the
  member as of the response's position (`member_event_at_position`, current state standing in when the position is
  not readable).

### Positive Consequences

* A backlog of any size is delivered `limit` events per response, and a lost response is retried safely.
* No client-visible change to classic `/sync` or to `StreamToken`.
* The worker never serves a sticky event its row no longer allows.

### Negative Consequences

* A sliding sync `pos` is no longer a bare `StreamToken`; code that reads one must use `decode_sliding_sync_pos`.
* A member sent as of the response can be later than the sticky event it is for. The client has no earlier place
  to put it.

## Pros and Cons of the Options

### A sticky component in `StreamToken`

* Bad, because ADR-0855 rejected it: classic `/sync`, `/keys/changes` and every token reader would change for a
  sliding sync problem.

### A random nonce per response

* Good, because it is simple.
* Bad, because a retry would be answered with a different `pos`, so the retry and the original are two responses for
  one request, and the connection state would have to remember every nonce it issued.

### Allocating a sync stream ID

* Bad, because a read would move server-wide state, which a token-driven request must never do, and every other
  connection on the server would wake for nothing.

### Anchoring a sticky sender's member at the oldest sticky event

* Bad, because that event can sit before the timeline's start, where the client cannot place a member, and a sender
  who joined later has no member there.

## Links

* Refines [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)
* Refines [ADR-0857](0857-a-room-holds-a-bounded-number-of-sticky-events-shared-fairly-between-servers.md)
* Refines [ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)
* Relates to [ADR-0221](0221-a-grown-sliding-sync-timeline-limit-skips-the-long-poll-once-per-request-pos.md)
