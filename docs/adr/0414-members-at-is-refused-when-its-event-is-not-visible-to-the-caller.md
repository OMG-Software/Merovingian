# GET /members?at= is refused when the event at that position is not visible to the caller

* Status: accepted
* Date: 2026-11-03

Technical Story: finding F-61 (low) in security audit run 2. Extends
[ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md).

## Context and Problem Statement

`GET /rooms/{roomId}/members?at=` returns the roster recorded for the newest accepted event at or before
`at`. ADR-0084 caps that position from above, at a departed user's leave, and says nothing about a lower
bound. A user who joined a `joined`-visibility room late could therefore ask for `at=1` and be given the
`m.room.member` events of a time Room History Visibility hides from them: past members, superseded display
names and avatars, kick and ban reasons. Every timeline route judges each event with
`HistoryVisibility::can_see`; this state route did not. Which check does `at` need, and on what?

## Decision Drivers

* The roster at a position is the state after one event. State the user may read is state at an event they
  may see (ADR-0084), so one judgement can cover the whole answer.
* The handler runs under `runtime.mutex`. F-10 made the roster cost O(members); a judgement per returned
  member would put a lookup per member back.
* The spec's 200 for a joined caller is "the current members" and for a departed one "the members of the room
  when you left". Both rosters contain members who joined before the caller did, and the caller may read them.

## Considered Options

* Judge the event the position resolves to, and refuse the request when the caller may not see it.
* Judge each returned `m.room.member` event with `can_see` and drop those it rejects.
* Clamp `at` up to the caller's join and answer with that roster.

## Decision Outcome

Chosen option: the first. `sync::state_anchor_event` finds the newest accepted event at or before the
position (for a departed user never later than the boundary event), the same event the roster is read from.
When the request carries `at`, the handler requires `HistoryVisibility{store, user}.can_see` on that event
and otherwise answers `403 M_FORBIDDEN`. `sync::state_event_ids_after` then reads the state recorded for that
very event, so the event judged and the event read cannot differ and the store is scanned once.

A position before the room's first event has no anchor and answers an empty roster: nothing is disclosed.
The check applies only where the client chose the position. Without `at`, a joined caller is given the
current roster and a departed caller the roster at their leave, neither of which is client-chosen.

Rejected alternatives:

* *Dropping member events `can_see` rejects.* It is wrong, not only costly. In a `joined` room the roster a
  caller may read at a position they can see holds members who joined before them, and `can_see` hides
  exactly those events from them as timeline events. Filtering would empty the roster of everyone who was
  there first, for the current-style answer and for the "members when you left" answer the spec requires. It
  also costs a lookup per member under `runtime.mutex`. The audit's remediation suggested it as defence in
  depth; it is not adopted.
* *Clamping `at` to the caller's join.* It answers a question the caller did not ask, and the caller cannot
  tell the position was moved.

### Positive Consequences

* A later joiner gets nothing from before their window through `at`, whatever the token or integer.
* The cost per request is the one store scan it already had plus one `can_see`.

### Negative Consequences

* A client that stored a `prev_batch` from before it joined and asks `/members?at=` with it now gets 403.
  Such a token names a point the caller was not entitled to see.
* The 403 is for a position, while the spec lists 403 only for "You aren't a member of the room and weren't
  previously a member of the room". The spec defines no response for an invisible position; 403 `M_FORBIDDEN`
  is the nearest and matches the refusal the same caller already gets for the room.

## Links

* Extends [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md) (the cap from
  above at a departed user's leave; this is the bound from below).
* Spec: Client-Server API v1.19, "Room History Visibility" and `GET /rooms/{roomId}/members`.
