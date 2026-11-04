# `GET /sync` honours `full_state=true` for joined rooms

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`full_state` was parsed and ignored. Lazy-loading's own-membership rule and the tracker rule both depend on it, and the
spec says "all state events will be returned, even if `since` is non-empty".

## Decision Outcome

A joined room's `state` is built as for an initial sync (the state at the start of the timeline) when `full_state=true`,
rooms with nothing to report included. Left rooms are not changed: an incremental left room keeps its delta state, which
holds the leave. Lazy-loading with `full_state=true` forces the user's own member event and does not consult the tracker.
