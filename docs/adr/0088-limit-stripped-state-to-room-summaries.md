# Limit stripped invite and knock state to room summaries

* Status: accepted
* Date: 2026-10-02

## Context and Problem Statement

Matrix v1.19 requires stripped state events to contain only `sender`, `type`,
`state_key`, and `content`, and requires the create event in client invite and
knock state. The specification permits additional event types; it does not
require disclosing a room's complete state to a prospective member.

The CSAZ-7 audit finding showed that invite snapshots and knock summaries
exposed full events, other members, and private room state. Merely projecting
all events onto the required four keys would still disclose those events'
contents. Filtering only newly generated snapshots would also leave historical
and federated snapshots exposed.

## Considered Options

* Project every state event onto the four-key schema.
* Restrict newly generated snapshots, trusting persisted snapshots on read.
* Apply a restrictive room-summary policy at both generation and client reads.

## Decision Outcome

Chosen option: "Apply a restrictive room-summary policy at both generation and
client reads", to minimize disclosure before a user joins and avoid trusting
historical or remotely supplied snapshots.

Expose only these empty-state-key room-summary types:

* `m.room.create`
* `m.room.name`
* `m.room.avatar`
* `m.room.topic`
* `m.room.join_rules`
* `m.room.canonical_alias`
* `m.room.encryption`

Also permit the recipient's own `m.room.member` event, never the other members'
roster. Project each admitted event onto the four-key stripped schema and reject
malformed entries. This allowlist is our disclosure policy, not a protocol
prohibition on other event types.

Persist stripped local invitation snapshots and re-prune snapshots when serving
clients, including legacy `/sync` and sliding-sync invite consumers. Preserve
invitation-time room decoration rather than replace it with current state.
Deduplicate invitation state by `(type, state_key)`; the actual invitation takes
precedence over a stale own-membership entry. Keep producer and read-side policy
changes synchronized and covered by regression tests.

### Positive Consequences

* Prospective members do not receive other members' membership events, ACLs, power levels,
  custom private state, or full event metadata through these summaries.
* Historical and federated full-event snapshots are not trusted as client-ready
  stripped state.
* Invitation-time decoration is retained while mandatory schema pruning is
  enforced.

### Negative Consequences

* Clients cannot use custom state types as pre-join decoration without an
  explicit, reviewed policy extension.
* Read-side validation remains necessary even though new local snapshots are
  already stripped.

## Links

* [Matrix v1.19 stripped state](../matrix-v1.19-spec/client-server-api.md#stripped-state)
* [CSAZ-7 audit finding](../security-audit-report-2026-09-29.md)
