# An outlier with no state group is not judged by its stream ordering

* Status: accepted
* Date: 2026-11-03

Technical Story: finding F-65 (low) in security audit run 2. Amends
[ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md).

## Context and Problem Statement

ADR-0084 gave an event with no state group rule 2 alone, judged from the user's own membership timeline
against the event's stream ordering. The justification was history stored before ADR-0064, where stream
ordering matches arrival order and the rule can only show a subset of what the spec allows.

ADR-0069 and ADR-0070 store events fetched as history (a `/state_ids` snapshot, `/event_auth`, a
`timestamp_to_event` answer) as `outlier` rows with no state group when their state before is not known, and
give them a fresh stream ordering: the time of the fetch. Judged by rule 2 from that number, every user joined
at fetch time passes, however old the event is in the room, so superseded pre-join state reached the `/sync`
timeline of a user in a `joined` or `invited` room. ADR-0308 already says never to order by stream ordering
where the question is before or after in the room.

## Decision Drivers

* An event whose place in the room is unknown must not be shown on the strength of when it was stored.
* Genuine pre-ADR-0064 rows must keep the rule-2 behaviour ADR-0084 chose, or upgraded deployments lose
  history.
* The user's own membership outlier (an invite received for a room whose state is not held, the leave that
  rejected it) must stay visible to that user (ADR-0304).

## Considered Options

* In `HistoryVisibility::can_see`, deny an event with no state group whose status is `outlier`, after the
  ADR-0304 exception.
* Exclude outliers where each read path builds a timeline.
* Give every fetched outlier a state group.

## Decision Outcome

Chosen option: the first. `can_see` returns false for a group-less `outlier` unless it is the user's own
`m.room.member` event (ADR-0304, unchanged). A group-less row that is not an outlier keeps rule 2. Rows from
before ADR-0064 have the default status `accepted`, so they are unaffected. When a later snapshot gives an
outlier a state group (the ADR-0070 promotion, which also authorises it), the ordinary five-rule check applies
from then on.

Every client read path already asks `can_see`, and `can_see` is the one place every one of them shares, so one
change covers `/sync`, sliding sync, `/messages`, `/context`, `/event`, `/search`, `/relations`, `/threads`
and `/timestamp_to_event`. No caller needs a group-less outlier other than the user's own membership one: the
invite and knock a user was sent, and the leave that rejected an invite, are their own membership events;
auth-event reads for federation use the federation read filter, not this class.

Rejected alternatives:

* *Excluding outliers in each timeline loop.* Nine paths would each carry the rule, and the next path added
  would forget, which is the reason ADR-0084 made `can_see` the one filter.
* *Giving every fetched outlier a state group.* The state before is unknown by construction; inventing a group
  would make the visibility of the event a guess.

### Positive Consequences

* A fetched pre-join event is never delivered by its fetch time.
* No new state, scan or lookup: the check is a status comparison on a path that already returned early.

### Negative Consequences

* An outlier a client could usefully see (shared history fetched by `timestamp_to_event`, with its state before
  unknown) is hidden until a snapshot gives it a state group. `timestamp_to_event` steps over it, as over any
  event the user may not see (ADR-0299).

## Links

* Amends [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md) (the
  "event with no state group gets rule 2 alone" bullet applies to non-outlier rows only).
* Builds on [ADR-0070](0070-event-auth-outliers-carry-no-state.md), [ADR-0304](0304-a-users-own-outlier-membership-event-is-visible-to-them.md)
 and [ADR-0308](0308-shared-history-visibility-orders-the-join-and-the-event-by-depth.md).
