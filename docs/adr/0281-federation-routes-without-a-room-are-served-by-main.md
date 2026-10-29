# Federation routes that name no room are served by main, not a worker snapshot

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestRemoteAliasRequestsUnderstandUnicode`)

## Context and Problem Statement

A federation worker answers room-scoped reads from a snapshot of its shard's rooms, refreshed per room
when main says a room changed. `GET /query/directory` names an alias, not a room: the worker answered it
from the `room_aliases` table it loaded at start-up, which nothing refreshes, so every alias created after
the worker started was 404.

## Decision Outcome

A route with no room ID cannot be served from a room-scoped snapshot. `query/directory` is relayed to
main (`directory_query_ingest`), like `query/profile`, `user/devices`, `event` and the key routes
already were. A federation endpoint added later that names no room is relayed to main, and
`federation_endpoint_requires_main_relay` lists it.
