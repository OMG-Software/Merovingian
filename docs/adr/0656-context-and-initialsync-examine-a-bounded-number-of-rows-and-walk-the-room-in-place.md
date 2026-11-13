# /context and /initialSync examine a bounded number of rows and walk the room in place

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C39 (hidden-event walks with no examination budget).

## Context and Problem Statement

`GET /rooms/{id}/context/{eventId}` and `GET /rooms/{id}/initialSync` copied a pointer to every non-rejected event of the
room into a vector and then stepped through it, asking `HistoryVisibility::can_see` of each candidate until a page of
visible events was full. Neither had an examination budget, unlike `/messages` (`max_messages_events_examined`). When the
events next to the reader's window are invisible to them (a user who left, a member of a `joined`-visibility room reading
before their join), the walk ran to the end of the room's history under `runtime.mutex`.

## Decision Drivers

* No read handler examines more rows than a configured number per request under the lock.
* The tokens handed back must let the client carry on, as `/messages` does when its budget ends (ADR-0470).
* Behaviour is unchanged whenever the budget is not reached.

## Considered Options

* Apply `max_messages_events_examined` to the walks, count every row looked at (visible or not), end the walk at the
  budget with the token at the last row examined, and walk the room's index in place instead of copying it.
* A new `max_context_events_examined` setting.
* Keep the copy and only add the budget.

## Decision Outcome

Chosen option: the first.

* `/context` finds the target by binary search on its stream ordering in `room_in_stream_order` and walks outwards
  from it; the before walk and the after walk each have the full budget, so a hidden stretch on one side does not starve
  the other. A row that is rejected, soft-failed, filtered, ignored or not visible counts as examined. When the budget
  ends a walk before its page is full, `start` or `end` is the stream ordering of the last row examined.
* `/initialSync` walks the room newest first in place with one budget, and when it ends before the page is full the
  tokens are those of the last row examined.
* The existing setting is reused: one number bounds every room read that steps over rows a reader may not see, and a
  second setting would have to be kept in step with it.

### Negative Consequences

* A reader whose nearest visible event lies further than the budget away gets an empty or short page and a token to
  continue from, where before they got that far event. Pagination with `/messages` reaches it.
* `/context` may examine up to twice the budget (once per side).

## Links

* Builds on ADR-0435 (room stream index), ADR-0470 (/messages budget token), ADR-0616.
