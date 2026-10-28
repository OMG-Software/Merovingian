# Presence is shown only to users who share a room

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (C1); owner decision 2026-10-28 to implement presence with a switch

## Context and Problem Statement

Presence was unimplemented. The spec leaves visibility, the cost of `set_presence`, and inbound limits open.

## Considered Options

* Visible only to users sharing a joined room, 403 otherwise (also for a user who does not exist); change on state change only; inbound bounded; `presence.enabled` default true
* Answer 404 for a missing user
* Stamp presence on every /sync poll
* Store any presence an origin sends

## Decision Outcome

Chosen option: "Visible only to users sharing a joined room, 403 otherwise (also for a user who does not exist); change on state change only; inbound bounded; `presence.enabled` default true", because the same 403 for a missing user prevents account enumeration; stamping every poll would cost a write and an EDU per sync under runtime.mutex; unbounded inbound presence is unbounded growth. A local user with no presence reads `offline`; a remote one 404. Inbound `m.presence` keeps an entry only for a user of the origin who shares a joined room with a local user, at most 100 entries per EDU and 1024 bytes of `status_msg`. With `presence.enabled=false` (restart required): GET 404, PUT 200 storing nothing, no presence in `/sync`, no EDUs either way.

### Positive Consequences

* Presence works for clients and over federation at bounded cost.

### Negative Consequences

* No idle timeout: a user who stops syncing keeps their last state, and a remote `online` never expires.
* A server newly joining a room is not sent current presence until it changes.
