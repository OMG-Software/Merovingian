# Device-list updates apply in stream order, a gap marks the list stale, and the cache is bounded

* Status: accepted
* Date: 2026-11-07

Technical Story: project analysis, finding G14; [ADR-0560](0560-remote-device-lists-are-cached-in-memory-for-shared-room-users-and-filled-from-user-devices.md).

## Context and Problem Statement

The spec says an `m.device_list_update` "which refers to a prev_id it does not recognise" means the server "must
resynchronise its list", and that `prev_id` "may be missing or empty for the first EDU in a sequence". It does not say
which IDs count as recognised after a snapshot, what to do with an empty `prev_id` when a list is held, what happens
to an update that arrives while a fill is in flight, or how large the cache may grow.

## Considered Options

* Recognise a `prev_id` at or below the snapshot's `stream_id`, or one of the last 8 applied; resync on anything else,
  including an empty `prev_id`; void a fill an update overtakes; bound users, devices and bytes.
* Recognise only `prev_id`s equal to IDs this server saw, and apply an update with an empty `prev_id`.

## Decision Outcome

Chosen option: the first.

* **Recognised `prev_id`s.** The snapshot reflects every update up to its `stream_id`, so any `prev_id` at or below it
  is accounted for; above it, only the stream IDs of the last `remembered_stream_ids` (8) applied updates are. An
  update whose `stream_id` is at or below the list's is already in it (`unchanged`: a re-sent transaction, or covered
  by the snapshot). Matching only seen IDs would resync after every snapshot, since a server's next `prev_id` names
  an update sent before the snapshot was taken.
* **Empty `prev_id` with a list held: resync.** It starts a sequence this list cannot place; applying it would hide
  any change sent before it that was lost. The cost is one `GET /user/devices` on the next query.
* **A gap or an unreadable update marks the list stale** (`resync_needed`). The EDU is still reported in
  `device_lists.changed`, and the next `/keys/query` fills the list again. `m.signing_key_update` also marks the list
  stale rather than editing the cached cross-signing keys: the next fill reads them with the devices, through the one
  checked reader.
* **Only a real change is reported.** An applied update that leaves the device as held (`unchanged`) writes no
  `device_list_changes` row and wakes no sync. `uncached`, `changed` and `resync_needed` are reported as before.
* **A fill an update overtakes is not kept.** `begin_resync` gives a ticket before `runtime.mutex` is released for the
  call; an update, `mark_stale` or `erase` meanwhile voids it, and `store_snapshot` refuses the answer, which may
  predate the update.
* **Bounds:** at most 10,000 users, 512 devices and 1 MiB per user, 64 MiB in all. A list over a cap is not held, so
  its user is served as before the cache; a full cache refuses new users rather than evicting, because an evicted
  user's next update is reported anyway and nothing is lost but the saving.

### Negative Consequences

* A server that sends empty `prev_id`s for every update costs one fill per update for its users.

## Links

* Refines [ADR-0560](0560-remote-device-lists-are-cached-in-memory-for-shared-room-users-and-filled-from-user-devices.md)
