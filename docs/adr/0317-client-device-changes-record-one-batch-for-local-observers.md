# Client device changes record one batch for local observers

* Status: accepted
* Date: 2026-11-02

Technical Story: security audit run-2 F-04, key and device endpoints committed once per room member under `runtime.mutex`

## Context and Problem Statement

`/keys/upload`, `/keys/device_signing/upload`, `/keys/signatures/upload` (even with an empty body),
`PUT` and `DELETE /devices/{deviceId}`, `/delete_devices`, `/logout` and `/logout/all` looped over every member of
every room the caller shares, remote members included, committing one `device_list_changes` row per member. A
federated room's roster is chosen by a remote server and reaches tens of thousands of members, so one trivial
request held `runtime.mutex` for that many commits. ADR-0265 already says device-list rows for a change are one
batch; these paths predated it. A row naming a remote observer was never read: `device_lists.changed` is served
to local users, and remote servers learn through `m.device_list_update`.

## Considered Options

* One helper, `record_shared_room_device_changes`: local observers only, deduplicated across rooms, one batch
* Keep rows for remote observers, in one batch
* Move the fan-out to a background job

## Decision Outcome

Chosen option: "One helper", because it gives one stream position and two commits (the watermark, then the rows) whatever the roster holds, and
stores nothing that is never read. Keeping remote rows would leave the batch's size and the table's growth in a
remote server's hands. A background job adds a queue and a delay between a key upload and the observer's next
sync for work that is now small. Each call site says whether the caller's own devices get a row, as they did
before.

### Positive Consequences

* Rows and lock-held work follow the number of local users, not a room's roster.
* A user sharing several rooms with the caller gets one row.

### Negative Consequences

* All rows of one change share a stream position, so a client's sync sees them together. That is correct: they
  are one change.

## Links

* Refines [ADR-0265](0265-membership-changes-reach-the-room-roster-through-one-function.md)
