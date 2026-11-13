# A space hierarchy request is answered by main, not by a worker snapshot

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

`GET /_matrix/federation/v1/hierarchy/{roomId}` was answered by a federation worker from its in-memory store, but the
proxy's shard key extractor has no entry for the path, so every request went to shard 0. A worker's copy of a room is
refreshed only by its owning shard's `room_sync`, so shard 0's copy of any room another shard owns is the snapshot from
start-up. The room ACL check, the "may this server view the room" decision and the summary ran on stale state: a server
added to a server ACL deny list, or a room whose join rule was tightened, after start-up kept receiving the summary of
the space and of its children (run-3 finding C47).

## Considered Options

* Main answers a hierarchy request itself (`federation_request_should_bypass_worker`)
* Add the path to the shard key prefixes
* Relay `space_hierarchy` to main from the worker, as `make_join` is

## Decision Outcome

Chosen option: "Main answers a hierarchy request itself". The proxy has already verified X-Matrix in main and main's
store is current for every room, whichever shard owns it. Main applies the same ACL and view checks through the same
federation core, and its provider now reads under `runtime.mutex` (ADR-0711).

Why not the shard key alone: it would make the space current but not its children, which any shard may own, which is the
finding's own caveat. Why not a worker relay: it keeps a hop and an IPC round trip to reach the same main provider, and
needs a worker-side override beside the one for `make_join`; the bypass is the existing mechanism for requests main must
answer (edu-only `/send`, media, `exchange_third_party_invite`).

Residual: `/send` is routed by its first PDU's sender-chosen room ID, which is the same staleness, but main re-checks ACL
and signatures on every relayed PDU.
