# Gap recovery fetches events with GET /event and keeps /event_auth as a last resort

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A8)

## Context and Problem Statement

To place a PDU whose history this server lacks, recovery asked `/get_missing_events` (with `latest_events` and `earliest_events` reversed against the spec), then `/state_ids`, then fetched the snapshot's auth chain with `/event_auth`. A peer need not serve `/event_auth`, and Complement's servers do not, so such PDUs were never placed.

## Considered Options

* Fetch every event `/state_ids` names with `GET /event/{eventId}`, auth chain first, and use `/event_auth` only as a last resort
* Keep `/event_auth` as the primary path (ADR-0069)
* Ask `GET /state/{roomId}` for the whole snapshot in one call

## Decision Outcome

Chosen option: "Fetch every event `/state_ids` names with `GET /event/{eventId}`, auth chain first, and use `/event_auth` only as a last resort", because it asks a peer only for what the spec requires it to serve. All named events are fetched before any is stored; a 404 on one ends the attempt with nothing stored. An event whose state-before is unknown is verified against its own `auth_events` and stored as an ADR-0070 outlier. `/get_missing_events` now sends the PDU as `latest_events` and up to ten forward extremities as `earliest_events`; a fetched PDU that cannot be placed is held for the recovery (bounded, unpersisted, re-verified when placed) and the state is asked at the nearest prev event nothing supplies. `GET /state` was not chosen in this change; it remains the cheaper option if per-event fetches prove too slow for long gaps.

### Positive Consequences

* PDUs with missing history are placed against peers that serve only the required endpoints.

### Negative Consequences

* A long gap costs one round trip per missing event, within `max_snapshot_outbound_calls`.

## Links

* Refines [ADR-0069](0069-spec-conformant-state-ids-fallback-via-event-auth.md)
* Relates to [ADR-0070](0070-event-auth-outliers-carry-no-state.md)
