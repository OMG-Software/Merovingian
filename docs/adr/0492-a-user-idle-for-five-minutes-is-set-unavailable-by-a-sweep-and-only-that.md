# A local user idle for five minutes is set unavailable by a 30 second sweep, and nothing sets a user offline

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

Client-Server API v1.19, Presence, "Idle timeout": "The server will automatically set a user's presence to
`unavailable` if their last active time was over a threshold value (e.g. 5 minutes)." The spec names no value and gives
no mechanism. Until now a user who stopped syncing stayed `online` for ever, because a presence row changed only when the
user, or their own server, said so.

## Decision Outcome

`presence_idle_timeout_ms` is five minutes, the spec's example. The `presence-idle` `PeriodicJob` runs
`run_presence_idle_sweep` every `presence_idle_sweep_interval` (30 s). Under `runtime.mutex`, with no network call, it sets
every local user whose presence is `online` and whose last active time (`presence_last_active_ago`) is over the threshold to
`unavailable` with `currently_active` false, through `record_presence`, queues the `m.presence` EDU for the servers that
share a room with them and wakes long-polling syncs. A user's own next `/sync` without `set_presence=offline` marks them
`online` again, as the spec's last sentence of that section asks.

* Only `online` rows change. `unavailable` and `offline` were chosen by the user or by their server.
* Only local users change. A remote user's presence is that server's to say (the EDU binds `user_id` to its origin).
* The threshold is a constant, not an option. The spec's own example is the value; an option can be added with no change of
  behaviour if an operator ever needs another.
* Nothing sets a user `offline` when they stop syncing. The spec defines `offline` as "not connected to an event stream"
  but asks for no timer, and which silence counts as a disconnect (a long-poll that ended, a closed socket, a missed
  poll) is a product choice the spec does not make.
* A sweep, not a check at read time. Reporting `unavailable` only when a presence is read would leave `/sync`
  `presence.events` and the federation EDU saying `online`, and no change would ever be sent.

## Consequences

A user is `unavailable` at most `presence_idle_sweep_interval` after crossing the threshold. Sending a message does not
bump the last active time today (only `/sync` and `PUT /presence` do), so a user whose client syncs with
`set_presence=offline` and only sends messages becomes `unavailable`.
