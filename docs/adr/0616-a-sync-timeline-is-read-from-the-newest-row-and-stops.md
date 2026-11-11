# A sync timeline is read from the newest row and stops

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, classic sync reads a room's whole history to return its newest events

## Context and Problem Statement

`/sync` built each joined and left room's timeline by walking every row of the room, oldest first, testing each one, and
then keeping the last `timeline_cap`. A sync of a room with a long history cost that history, under `runtime.mutex`, on
every poll, and a remote server chooses how long a federated room's history is.

## Decision Drivers

* The work under `runtime.mutex` must not grow with what a remote server chooses.
* `limited`, `prev_batch` and the state returned must stay what they were for a response the walk finishes.

## Considered Options

* Walk newest first and stop at the limit plus one, with no other bound
* Walk newest first and stop at the limit plus one, and also stop after a fixed number of rows not taken
* Cache each room's window between requests

## Decision Outcome

Chosen option: "Walk newest first and stop at the limit plus one, and also stop after a fixed number of rows not taken".

`sync::newest_timeline_window` seeks both ends of the window in `EventTable::room_in_stream_order` and walks down from the
newest row. It stops holding `cap + 1` rows: one more than the limit is what says older events were left out, so
`limited` and `prev_batch` come out as before. It also stops after `max_timeline_rows_skipped` (1000) rows it did not
take, which only a filter or a visibility rule that refuses that many rows in a row reaches. Then the response says
`limited: true`, since older events may have been left out, and `prev_batch` is the window's oldest event or, for an empty
window, the oldest row read, so a client paginates on from where the walk stopped.

### Rejected: no bound on rows not taken

A filter on a type the room does not hold, or a user who cannot see the room's history, would read the whole room as
before. The finding would stand for exactly the requests a low-trust account can shape.

### Rejected: a cached window

A cache filled while reading needs synchronising (ADR-0525) and a rule for every writer of the event table, to save
work that is now the size of the response.

### Negative Consequences

* Past the budget, `limited` can be true where a complete walk would have found fewer than the limit and said false. The
  client paginates and sees the same events. This is the one change in what `/sync` answers.
