# Membership changes reach the room roster through one function

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A11)

## Context and Problem Statement

Three paths changed a room's in-memory roster: local composition, the membership acceptor and PDU ingestion. Only the first recorded device-list changes, so a remote leave never produced `device_lists.left`. Separately, Complement expects a user who joins over federation in their own `device_lists.changed`; the spec allows a liberal `changed` ("a server may add Alice to `changed` when Alice and Bob share a new room").

## Considered Options

* One function, `apply_membership_to_roster`, used by all three paths; list a federated joiner in their own `changed`
* Each path edits the roster itself
* Never list a user in their own `changed`

## Decision Outcome

Chosen option: "One function, `apply_membership_to_roster`, used by all three paths; list a federated joiner in their own `changed`", because separate edits are how `left` was lost. The joiner is listed only on the federated join path, so their other devices refresh keys, without adding noise to every local room creation. Device-list rows for a change are written as one batch.

### Positive Consequences

* Remote joins and leaves update `device_lists` like local ones.

### Negative Consequences

* A new membership path must call this function.
