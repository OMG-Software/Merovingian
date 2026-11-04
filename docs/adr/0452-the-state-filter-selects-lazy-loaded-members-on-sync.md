# The `state` filter selects lazy-loaded members on `/sync`

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

On `/messages` and `/context` the RoomEventFilter's `types` and `senders` select chunk events, so lazy-loaded members must
ignore them. On `/sync` the `state` filter selects state events and nothing else, and the spec says "Lazy-loading members
is only supported on the `state` part of a RoomFilter for this endpoint".

## Decision Outcome

Chosen option: on `/sync`, lazy-loading is on only when `room.state.lazy_load_members` is true (the same flag on
`room.timeline` does nothing), and the state filter's `types`, `not_types`, `senders` and `not_senders` apply to the
member events like any other state event. So `not_types: ["m.room.member"]` with lazy-loading yields no member events, not
even the user's own, and a `types` list without `m.room.member` the same. That contradicts the spec's MUST to include the
own membership; it is an explicit, contradictory request from the client, and the filter wins. A filtered-out member is
neither sent nor recorded.

The member events are exactly the union of: the member event, as of the start of the timeline, of each sender of a
delivered timeline event (subject to redundancy); on a limited incremental sync every member state change in the gap,
whoever it is about (never redundant); and the user's own member event when they joined in this response's window or full
state was requested, unless their join is in the timeline. Heroes get nothing extra and the room summary keeps its true
counts. Applies to `join` and `leave` sections; invite and knock stripped state and sliding sync are untouched.
