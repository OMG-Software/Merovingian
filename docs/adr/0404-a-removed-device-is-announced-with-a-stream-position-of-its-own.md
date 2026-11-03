# A removed device is announced with a stream position of its own

* Status: accepted
* Date: 2026-11-03

## Context and Problem Statement

Spec v1.19 (SS API, Device Management) has a server send `m.device_list_update` to every server that shares a room with
a local user whenever the user's device list changes, "for new or deleted devices" included, and calls `stream_id`
"unique for a given user_id". This server sent the EDU only for devices that still exist and always with `prev_id: []`,
reading the sync counter's current value as the `stream_id` without taking a position. A deleted device has no row to
read, and several deletions in one request would share one counter value. How is the deletion EDU numbered?

## Decision Drivers

* `stream_id` must differ between the EDUs of one user, or a receiver cannot tell two deletions apart.
* The announcement must be enqueue-only and bounded by the request: it runs under `runtime.mutex`.
* Nothing may persist a second per-user sequence that has to be kept in step with the sync counter.

## Considered Options

* Read `next_sync_stream_id` as the existing broadcast does.
* Keep a persisted per-user "last EDU stream_id" and chain every `prev_id` from it.
* Take a position from the sync counter for each deleted device (`allocate_sync_stream_id`) and name the previous EDU of
  the same call in `prev_id`.

## Decision Outcome

Chosen option: "take a position from the sync counter for each deleted device", because it is the counter every other
device-list change already uses, it makes each `stream_id` unique, and it needs no new state. `announce_deleted_devices`
allocates one position per device, builds `build_device_deleted_update_content` (`deleted: true`, no `keys`), and
enqueues one EDU per server. `prev_id` holds the position of the EDU announced just before it in the same call and is
empty for the first, as in every other `m.device_list_update` this server sends. The servers are read with
`remote_servers_for_user` before the removal. At the counter's ceiling (ADR-0315) the removal stands and the
announcement is skipped with a warning.

### Positive Consequences

* A receiver that misses one deletion of a batch sees an unknown `prev_id` and resyncs through `/user/keys/query`.
* No schema change.

### Negative Consequences

* A position is consumed with no `device_list_changes` row behind it, so sync positions have gaps (harmless: they
  already do, for ephemeral surfaces).
* `prev_id` does not chain across requests, so a lost EDU from an earlier request is not detectable by the receiver.

## Pros and Cons of the Options

### Read `next_sync_stream_id`

* Good, because it is what the existing broadcast does.
* Bad, because two deletions with no observer rows in between get the same `stream_id`.

### Persist a per-user last-EDU stream_id

* Good, because `prev_id` would chain across requests and give full gap detection.
* Bad, because it is a new table and a second sequence to keep in step with the sync counter, for a spec "should".

## Links

* Refines [ADR-0317](0317-client-device-changes-record-one-batch-for-local-observers.md)
