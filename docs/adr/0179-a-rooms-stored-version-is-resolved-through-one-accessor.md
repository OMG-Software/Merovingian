# A room's stored version is resolved through one accessor, and a join must match the create event

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1,
`rooms.room-version-resolution-divergent-fallbacks-create-without-room_version`

## Context and Problem Statement

A room's version is what its `m.room.create` declares, and a create event without `room_version`
is room version 1 (`client-server-api.md`, `m.room.create`), which this server does not support
(ADR-0076). Each component read the stored create event itself, with its own default when the
field was missing: `"1"` (power checks, redactions), `"10"` (the federation router and its PDU
version resolver), `"12"` (event composition). A federated join took the version from the
make_join answer and never checked the create event in the send_join state. A resident server could
therefore seat a local user in a room whose create event omits `room_version`, and the room was
then composed under one rule set, verified under another and refused by a third.

## Decision Drivers

* One room has one version, the one its create event declares.
* A missing or unusable declaration must never become a supported version.
* Inbound PDUs for rooms this server does not know are a separate path; this fix must not change it.

## Considered Options

* One accessor for the stored version; each caller keeps its own fallback only for a room with no
  stored create; a join is refused unless the create event declares the make_join version
* One accessor that also fails closed for unknown rooms
* Keep the per-component readers and only add the join check

## Decision Outcome

Chosen option: "one accessor; explicit fallbacks only for unknown rooms; a join must match".
`homeserver::declared_room_version` reads a create event: no `room_version` gives `"1"`; no
content object, or a value that is not a string, gives `""`. `homeserver::stored_room_version`
returns `nullopt` only when no create is stored; `stored_room_version_policy` returns the policy or
`nullptr`. Every reader of a stored create goes through them. Callers that need a value for an
unknown room write their fallback as `value_or(...)` at the call site.
`perform_federated_join` refuses the join (502) before anything is stored unless the verified
`m.room.create` in the send_join state declares the make_join version.

Auth rule 1.3 now also rejects a `room_version` that is present but not a string, as the spec says
("present and is not a recognised version").

### Positive Consequences

* A create without `room_version` resolves to version 1 everywhere, has no policy, and is refused.
* A resident server cannot choose the rule set by answering make_join with another version.

### Negative Consequences

* The unknown-room fallbacks (`"10"` in the router, `"12"` when composing) remain, now visible at
  their call sites.

## Pros and Cons of the Options

### Fail closed for unknown rooms too

* Bad, because inbound invites and PDUs for rooms not yet known rely on those fallbacks; changing
  them is a separate piece of work with its own tests.

### Join check only

* Bad, because the per-component defaults would still disagree for any create that reached the
  store another way.

## Links

* Refines [ADR-0076](0076-room-versions-1-and-2-are-not-supported.md)
