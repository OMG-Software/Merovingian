# /sync reports a leave once

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (C2)

## Context and Problem Statement

With `include_leave`, every incremental `/sync` listed every room the user had ever left. The spec calls `/sync` a delta, and says forgotten rooms "will never appear in the response to the /sync API"; Complement's TestRoomForget expects a forgotten room's leave in the next incremental sync.

## Considered Options

* An incremental sync lists a leave or ban once, after `since`; `include_leave` governs initial syncs only; a forgotten room is never listed
* List all left rooms whenever `include_leave` is set
* List a forgotten room's leave once, as Complement expects

## Decision Outcome

Chosen option: "An incremental sync lists a leave or ban once, after `since`; `include_leave` governs initial syncs only; a forgotten room is never listed", because it is the delta the spec describes, and the forget rule is the spec's own words. `rooms.leave` includes bans ("The rooms that the user has left or been banned from"). TestRoomForget's subtest is skip-listed with that quote.

### Positive Consequences

* Clients are told of a leave once, and forgotten rooms stay forgotten.

### Negative Consequences

* Complement TestRoomForget "Leave for forgotten room shows up in v2 incremental /sync" fails by design.
