# A sliding sync timeline is read through the shared window walk, with its skip budget

* Status: Accepted
* Date: 2026-11-12

Technical Story: security audit run 3, finding C08

## Context and Problem Statement

`build_room_response` built a sliding sync room's timeline by its own loop over the room's rows, newest first. It stopped
at `timeline_limit + 1` rows taken, but a row it did not take (hidden by history visibility, from an ignored sender,
rejected or soft-failed, or with no client JSON) was skipped without being counted. A room whose newest history the
caller cannot see was therefore walked to its first event on every initial build, under `runtime.mutex`, the cost per
row being a visibility check or a JSON parse. Classic `/sync` had the bound since ADR-0616.

## Considered Options

* Move the sliding sync loop onto `sync::newest_timeline_window`, and take `limited` and `prev_batch` from the result as
  ADR-0616 does.
* Keep the loop and add a counter of rows skipped.

## Decision Outcome

Chosen option: "move onto `newest_timeline_window`". There is then one walk, one budget (`max_timeline_rows_skipped`,
1000) and one counter (`sync_timeline_rows_examined`) for both syncs, and a future change of the budget cannot reach
one and miss the other.

* The window is the newest `timeline_limit + 1` rows that pass: visibility, the ignore filter, and a non-empty client
  JSON. The JSON built in the filter is kept for the rows taken, so it is built once per row, and a row that gives no
  JSON is still passed over and counted, as before.
* The floor of an incremental build is the `after` bound, and the upper bound the response's position, as before.
* When the budget runs out, `limited` is true: older events may have been left out. `prev_batch` is the oldest row
  taken, or, when none was taken, the oldest row read, so a client pages on from where the walk stopped.

### Rejected: a second counter in the sliding sync loop

It looks smaller, but it copies the budget and the rule for `limited` and `prev_batch` into a second place, and the two
drift. This finding is the result of exactly that.

## Consequences

* A sliding sync room whose newest 1000 rows are all passed over now returns an empty `limited` timeline with a
  `prev_batch`, where it returned older events. The client pages back with `/messages`, as classic sync clients do.
