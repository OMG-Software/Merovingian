# A room's tips from senders without power share one cap, that power holders are exempt from

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit C21,
`F-resource-exhaustion.forward-extremities.per-server-tip-limit-spent-across-many-server-names`. Refines
[ADR-0602](0602-a-server-is-limited-to-its-own-share-of-a-rooms-forward-extremities.md).

## Context and Problem Statement

ADR-0602 limits each sender server to `max_state_tips_per_server` (32) of a room's forward extremities, keyed on the
text after the sender's first `:`. A remote attacker runs as many server names as it likes (`evil.example`,
`a.evil.example`, `evil.example:8449`), so about 32 names in its own room again reach the `max_state_groups` (1,000)
tips that make every later PDU pay a resolution over all of them, and make the room's recomputation refused (ADR-0375).
ADR-0602 rejected a per-room limit because an attacker who fills it would keep an honest server's ban or demotion out of
resolution.

How are a room's tips bounded whatever the number of server names, without ever refusing an honest moderator?

## Decision Drivers

* An honest power holder's tips (a ban, a power-level change) are never refused because of tips anyone else added.
* The bound does not depend on how many server names one operator runs.
* No work per PDU under `runtime.mutex` grows with what a remote server chooses, beyond the room's tips.

## Considered Options

* A room-wide cap on the tips of senders who hold no power, with power holders always admitted.
* Charge each tip to the origin that delivered it rather than to the sender's server.
* Make the memo of the tips' resolution incremental, so many tips are cheap.

## Decision Outcome

Chosen option: "A room-wide cap on the tips of senders who hold no power", because it bounds what senders without power
can add jointly, however many names they run, and leaves every moderator's event a tip.

* A sender holds power in a room when, by current state, its effective level (room creators infinite from version 12)
  reaches the level needed to send `m.room.power_levels` or the `ban` level (`RoomPowerJudge::holds_room_power`).
* `event_may_become_forward_extremity` admits, in order: an event citing a current tip (unchanged); then, while the
  sender's server holds fewer than `max_state_tips_per_server` tips (ADR-0602, unchanged), an event from a power holder,
  or any event while the room's tips from senders without power number fewer than `max_unprivileged_state_tips`
  (default 128, `security.federation.state_resolution.max_unprivileged_state_tips`); and, past a cap, a message in a
  state group a tip already holds (unchanged). A message still first needs the room under `max_state_groups`
  (ADR-0374).
* A power holder stays under its own server's cap. Only that server's events fill it, so no other server can use it to
  keep a moderator's ban or demotion out, and a hostile moderator's server is still bounded to its own share. Exempting
  power holders from the per-server cap too was rejected: it would leave a hostile moderator's forks unbounded in every
  room it moderates, which ADR-0602 and its tests rule out.
* The judge is built only when the room's tips reach the joint cap, and asks each distinct tip sender once, so the
  usual PDU pays nothing more than before.

### Positive Consequences

* Senders without power add at most `max_unprivileged_state_tips` tips to a room jointly, whatever their server names.
* A ban, a demotion or a power-level change from a moderator reaches resolution whatever other servers add; only its
  own server's tips can refuse it.

### Negative Consequences

* Residual: power holders are bounded only per server name. In a room an attacker created, it holds power on every
  name it gives power to, and those names can still add `max_state_tips_per_server` tips each. A room it controls is the attacker's own cost under the runtime lock only
  while this server has a member there, and its tips past `max_state_groups` make that room's recomputation refused
  (ADR-0375), not other rooms'.
* Residual: while senders without power fill the joint cap, an honest member's state event that cites no current tip is
  stored and delivered but is not a tip, as past the per-server cap. An honest server normally cites the tips it knows,
  and an event citing a current tip is always admitted.
* Counting the joint cap reads each tip's event and the sender's level: linear in the room's tips, only once the room
  holds that many.

## Pros and Cons of the Options

### Charge tips to the delivering origin

* Good, because the origin is authenticated per request.
* Bad, because an attacker controls as many origins as server names: the same bound by another key.

### Incremental resolution of the tips

* Good, because it would make many tips cheap whoever sent them.
* Bad, because state resolution is not associative (ADR-0601), so a fold is not the resolution.

## Links

* Refines [ADR-0602](0602-a-server-is-limited-to-its-own-share-of-a-rooms-forward-extremities.md)
* Relates to [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md) and
  [ADR-0375](0375-a-refused-recomputation-of-current-state-is-a-status-not-a-success.md)
