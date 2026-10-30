# Room summaries answer unauthenticated callers uniformly, for local rooms only

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestRoomSummaryAllowedRoomIDs`)

## Context and Problem Statement

`GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` (added in v1.15) was not implemented.
The spec lets servers allow unauthenticated access when the room's join rule is `public`,
`knock` or `knock_restricted`, or its history is `world_readable`, and lets a server ask
another server through `via` for a room it holds no state for.

## Considered Options

* Answer an unauthenticated caller 404 for a room it may not see, as for a room that does not
  exist.
* Answer an unauthenticated caller one 401 `M_MISSING_TOKEN` for every room it may not see,
  existing or not.
* Ask the `via` servers for a room this server holds no state for.

## Decision Outcome

Chosen option: a uniform 401 `M_MISSING_TOKEN` without a token, 404 `M_NOT_FOUND` with one,
for local rooms only.

* Without a token, only a public, knock, knock-restricted or world-readable room is summarised.
  Every other room, and a room that does not exist, gets the same 401, so the answer does not
  tell a private room from a missing one.
* With a token, the caller sees what the space hierarchy would show them, plus rooms they are
  invited to or have knocked on; anything else, and a missing room, is 404.
* `via` is not used: a client-triggered federation call needs an ADR-0079 slot and deadline, and
  is tracked as a gap in `docs/todos/capability-gaps.md`. A future change that adds it takes
  those first.
