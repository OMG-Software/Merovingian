# A resident's claim about a local user does not move this server's record

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-authz.send-join-snapshot.overwrites-local-user-membership-with-resident-claim`.

## Context and Problem Statement

When a local user joins a room this server holds nothing of, the resident's `send_join` snapshot becomes current state, the
snapshot's state group and the membership rows. The resident is chosen by the joining user's `via`. An old, genuine join of
another local user (signed by this server, public in the room's history) passes every check, so a user this server banned,
or who left, was put back on the roster and in current state.

## Considered Options

* A claim about a user of this server is taken only when this server holds no membership row for that user in the room, or
  the claimed event is the one held as current. Otherwise the event is kept as an outlier and the snapshot's state group
  carries this server's own current event for the key (nothing, if this server holds none).
* Drop the key from the snapshot's state group.
* Prefer the newer of the two events.

## Decision Outcome

Chosen option: the first. The state group is the input of `recompute_current_state`, which since
[ADR-0615](0615-current-state-drops-a-key-the-resolution-does-not-hold-and-keeps-a-row-from-outside-the-graph.md) corrects
membership rows from the resolved state. A stale join left in the group would come back through the next recomputation even
if the first write were refused. Dropping the key would make that recomputation remove this server's own ban row.
Preferring the newer event trusts the resident's `origin_server_ts`, which the resident chooses.

The joiner's own join is not in the snapshot: it is stored after it and replaces the key in the group. The group is still
built from the entries the ingest returns; what changed is that the ingest returns this server's event for a refused key,
so the state group itself needed no change.
