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

## Amendments (same day, after review)

* **A message counts as activity.** The spec's "Last active ago" names "sending a message to a room" as a pro-active event.
  `send_event_as_user` calls `note_local_message_activity` after it stores a non-state event: an `online` row gets
  `last_active_ago` 0, `observed_at_ms` now and `currently_active` true, in memory (no stream position, no EDU, like the
  still-online case of `apply_sync_presence`). It makes no row for a user who has none and does not touch `unavailable` or
  `offline`. State events do not count: profile propagation sends them through the same function, and they are not the
  user's doing. Without this a user who only sends messages was set `unavailable`.
* **Sliding sync marks the user active** through `set_presence` (ADR-0495).
* **The clock starts at the first pass.** `observed_at_ms` is not persisted, and `presence_last_active_ago` adds elapsed
  time only when it is above 0, so a row loaded `online` with `last_active_ago` 0 would read 0 for ever and never be
  swept. The sweep sets `observed_at_ms` to now on any local `online` row that has none; the idle time runs from the first
  pass after start-up.
* **A pass is bounded.** Each user set unavailable costs a commit, a linear `find_if` in `upsert_presence`, an appservice
  queue entry and `remote_servers_for_user` (a scan of every room's members), all under `runtime.mutex`. A pass takes at
  most `presence_idle_max_per_pass` (100) users and, if it took that many, the job sleeps `presence_idle_catch_up_interval`
  (1 s) instead of the ordinary 30 s, so the lock is free in between and the rest follow.
