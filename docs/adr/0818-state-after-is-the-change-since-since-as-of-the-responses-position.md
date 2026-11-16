# `state_after` is the change since `since`, as of the response's position

* Status: accepted
* Date: 2026-11-16

## Context and Problem Statement

`GET /sync` with `use_state_after=true` answers `state_after`: "Updates to the state, between the time indicated by the
`since` parameter, and the **end** of the `timeline`", and a client "MUST only update their local state with events in this
list, and MUST NOT update their local state with events in `timeline`". The spec leaves open which point is the end of the
timeline when the timeline filter hides events, and how much a `limited` sync sends.

## Considered Options

* The end is the state recorded for the last delivered timeline event (rejected, see below)
* The end is the response's own position, `sync_position`, the point `next_batch` names
* A `limited` sync sends the whole state at the end of the timeline, as `state` does at its start (rejected, see below)
* A `limited` sync sends the changes since `since`, like any other incremental sync

## Decision Outcome

Chosen options: the response's position, and the changes since `since`.

The last delivered event is the wrong point because `next_batch` is past it. With `not_types: ["m.room.topic"]` on the
timeline, a topic change after the last delivered message lies before `next_batch`. The next sync starts after it, and the
client takes no state from the timeline, so a `state_after` as of that message would lose the change for good. Without a
filter the two points hold the same state, so this reading never contradicts the spec.

`state` sends the whole state on a `limited` sync because a client cannot otherwise tell what the gap changed. `state_after`
has no such gap: the delta ([ADR-0819](0819-a-state-after-delta-compares-the-two-states.md)) covers `since` to the position
whatever the timeline's size, so whole state would only repeat what the client has, on the requests that are already
largest. Whole state remains for what the spec names (no `since`, `full_state=true`) and for a room joined in the window,
where the client holds nothing to apply a delta to.

The parameter is parsed like `full_state`: `true` turns it on, anything else leaves it off. With it off, or absent, no
response changes. Sliding sync (MSC4186) has its own state model and is not changed.

### Consequences

* `state_after` can name an event after the last timeline event, when the timeline filter hid it. That event is not an
  update a client could have got any other way.
