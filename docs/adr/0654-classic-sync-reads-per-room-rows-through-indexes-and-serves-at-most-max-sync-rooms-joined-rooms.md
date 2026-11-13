# Classic sync reads per-room rows through indexes and serves at most max_sync_rooms joined rooms

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C34 (per-room scans of server-wide tables in `/sync`).

## Context and Problem Statement

After the release-gate fixes classic `/sync` still walked whole server-wide vectors once per joined room under the
runtime lock: the receipts (twice), `store.state` (once per joined room on every incremental sync, to ask whether the
user's own join is new, and again, up to twice, per emitted room on the state path), and `store.memberships` (once per
emitted room, for the invited count, the joined count and the heroes). The loop also counted only rooms that ended up in
the response against `max_sync_rooms`, so on an incremental sync every joined room paid the per-room cost.

## Decision Drivers

* The work of one `/sync` is proportional to the caller's rooms and those rooms' own rows.
* Indexed readers for state and memberships already exist (ADR-0344, ADR-0437); receipts got theirs in ADR-0737.
* The response must not change.

## Considered Options

* Move every per-room read onto its index and count processed joined rooms against `max_sync_rooms`.
* Cache per-room results across syncs.
* Only cap the rooms.

## Decision Outcome

Chosen option: the first.

* `joined_membership_changed_since` asks `find_current_state_event_id`; `build_current_state_events_array` and
  `build_state_events_at_position` visit `for_each_room_state_row`; `invited_member_count`, the joined-count fallback and
  the heroes fallback visit `for_each_room_membership_row`. Row order is the storage order the old scans had, so the
  response is unchanged. `state_rows_examined` counts the state rows these read, so a test proves the cost.
* `max_sync_rooms` bounds the joined rooms a sync does per-room work for. How the rooms are chosen, and what an
  incremental sync does with a room that cannot have news, is ADR-0658: the first version of this change counted every
  joined room in iteration order and so starved the rooms past the cap of their news; that is corrected there.

### The per-request variants

The walks of server-wide tables that a sync makes once per request, not once per room (the observer's device-list
changes, the user's stored filters, the push-rule classifier's room sources and the presence builder), are indexed by
ADR-0659.

## Links

* Builds on ADR-0344, ADR-0437, ADR-0603, ADR-0737, ADR-0616.
