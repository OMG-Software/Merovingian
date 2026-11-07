# GET /room_summary with a via asks the federation hierarchy endpoint and refuses a malformed via

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

`GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` takes `via`, "the servers to attempt to request the summary from when the local server cannot generate it". Matrix v1.19 defines no federation summary endpoint (the unstable MSC3266 route is not in the specification). Which federation route answers a room this server holds no state for, and what is done with a `via` that is not a list of server names?

## Considered Options

* Ask the unstable MSC3266 summary route.
* Ask `GET /_matrix/federation/v1/hierarchy/{roomId}` and use its `room` chunk.
* Refuse (ignore) every malformed `via` entry silently.
* Refuse the request with `400 M_INVALID_PARAM` when any `via` entry read is not a server name.

## Decision Outcome

Chosen: the stable hierarchy route, reusing `RemoteHierarchy` (the space-hierarchy walk's remote client), so the slot, deadline, 3-server cap, `OutboundAnswerTrust::unverified`, spec-field-only parsing and visibility check are shared rather than copied (ADR-0513). The `room` chunk is the summary; `children_state` is dropped and nothing else the remote server sent is kept or cached. A malformed `via` is `400 M_INVALID_PARAM` before any lookup or call, at most 8 `via` values are read, and this server's own name is never a target. Local state always wins; an alias is resolved only in this server's directory.

### Consequences

* A server that does not implement the hierarchy route cannot supply a summary; the answer is 404.
* A remote room is visible to an unauthenticated caller only when the remote summary is `public`, `knock`, `knock_restricted` (or has no `join_rule`) or `world_readable`.
* A user cannot tell from the answer whether a private remote room exists (404, or 401 without a token).
* `via` is validated even when local state would answer, so the same request has one answer whether or not the room is held.
