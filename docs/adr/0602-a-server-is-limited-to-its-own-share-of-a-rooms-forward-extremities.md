# A server is limited to its own share of a room's forward extremities

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit,
`F-resource-exhaustion.state-resolution.every-accepted-pdu-resolves-all-distinct-extremity-states-under-runtime-mutex`.
Refines item 3 of [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md).

## Context and Problem Statement

ADR-0374 made every accepted state event a tip, so that a ban or demotion always reaches resolution. One server could then
hold up to `max_state_groups` distinct state tips by sending that many state events citing old events, and each PDU in that
room cost a resolution over all of them.

How is that bounded without letting an attacker's forks push out an honest server's ban?

## Decision Drivers

* ADR-0374's driver stands: a ban or demotion must reach resolution whatever the room's forks.
* A server must not be able to spend another server's allowance.
* Counting must not parse or scan per tip per PDU.
* An event that is not a tip must not change current state for good.

## Considered Options

* A limit per room on state tips.
* A limit per sender's server, for events that cite no tip.
* A limit per sender user.

## Decision Outcome

Chosen option: "A limit per sender's server, for events that cite no tip". `event_may_become_forward_extremity` decides, and
`max_state_tips_per_server` (default 32, 1..4096) sets the limit.

* An event that cites a current tip replaces it and is never refused.
* Otherwise a server holding at least its limit of the room's tips adds no more. The event is still stored, delivered and
  given its state group, like the non-state case in ADR-0374.
* A server is charged only for events its users signed. An honest server's demotion is a tip however many tips a hostile
  server holds, so it reaches resolution and reverts that server's state.
* `ForwardExtremityTable` keeps the count per (room, server of the sender) as tips are added and removed. A tip is charged
  to its event's `sender`, whose domain the signature check bound to the signing server. Hydration reads tips before events,
  so `rebuild_forward_extremity_servers` charges them afterwards.

Three consequences of the rule are decisions of their own:

1. **Messages are limited too when they add a state group.** A message's after-state is its `prev_event`'s group, so a
   server past its limit could otherwise add tips, and distinct groups, by sending messages citing many old state events.
   A message past the limit stays a tip only if its one `prev_event`'s group is already held by a tip: it then adds nothing
   to resolve, and ADR-0374's flood of messages citing one event behaves as it did. That test is a hash lookup per tip, and
   runs only for a message past its server's limit that cites no tip.
2. **A state event that is not a tip writes no `current_state` row and no membership.** ADR-0375's own-row write relies on
   a later resolution reconciling it. No tip holds this event's state, so a key no tip holds would stay current for ever.
3. **`send_join`, `send_leave` and `send_knock` are refused instead, with 503 and nothing stored.** A join stored without
   taking effect is worse than none, and a resend would then be refused for not being current. A fresh `make_join` cites
   the current tips, so a retry succeeds.

### Positive Consequences

* One server's state forks cost at most `max_state_tips_per_server` tips in a room.

### Negative Consequences

* **Residual:** many colluding servers can still approach `max_state_groups` distinct tips between them, at
  `max_state_tips_per_server` each. Each needs a joined member able to send state. Past that, recomputation is refused
  (ADR-0375).
* An honest server that really does hold its limit of concurrent forks, citing none of them, has a later state event stored
  but not applied here until it builds on a tip. Thirty-two standing forks from one server is not ordinary behaviour.

## Pros and Cons of the Options

### A limit per room on state tips

* Good, because it bounds the resolution directly, including against collusion.
* Bad, because the attacker fills it first and an honest server's ban is then refused: the outcome ADR-0374 exists to prevent.

### A limit per sender user

* Good, because it is finer than a server.
* Bad, because a server mints users freely, so it limits nothing.

## Links

* Refines [ADR-0374](0374-forward-extremities-are-bounded-for-events-that-add-no-state.md)
* Relates to [ADR-0375](0375-a-refused-recomputation-of-current-state-is-a-status-not-a-success.md)
