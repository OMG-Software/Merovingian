# A user holds at most 200 devices, a device name at most 256 bytes, and a device-list announcement is linear

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-05.

## Context and Problem Statement

Device creation had no cap on a user's devices and none on a device's display name. A 900 KiB
`initial_device_display_name` was accepted and stored. `broadcast_device_list_updates` called
`build_device_list_update_content` once per device, and each call built a `DeviceDisplayNames` (a pass over every device on
the server) and ran a `find_if` over every device key: O(N x (D + K)) under `runtime.mutex`, about 5 seconds at 2,000
devices, repeatable at 120 requests a minute, stalling every client and federation request. Other per-user resources were
already capped; this one was missed. What bounds the number of devices and the size of a name, how is the limit enforced,
and how is the announcement made linear?

## Decision Drivers

* Work under the runtime lock must not grow faster than linearly with what one client controls.
* The Matrix specification names no device limit, so the shape of a refusal is ours to choose.
* The wire output of an `m.device_list_update` EDU must not change: a federation worker and conformance tests depend on it.

## Considered Options

* Cap devices at 200 per user and names at 256 bytes; refuse past either; build the announcement from one lookup and one index
* Cap the same, but evict the oldest device at the cap
* Cap the same, but truncate a long name
* Only make the announcement linear and cap nothing
* Make the caps configuration keys

## Decision Outcome

Chosen option: "cap devices at 200 per user and names at 256 bytes; refuse past either; build the announcement from one
lookup and one index", because it bounds both the stored data and the work, and every refusal leaves the account as it was.

* **Device count: 403 `M_FORBIDDEN`.** `complete_login` and `login_local_user_by_id` (every device-creating path ends in one
  of them) refuse a NEW device ID past `device_count_limit` (200), in the same place and shape as the refusal of a device
  ID that names a cross-signing key, before any row is written. 403 because the spec's login refusals are 403 and the
  request is well formed but not permitted for this account. A device ID the user already holds is always allowed: a
  client at the cap can still sign in again. The count is taken in the pass that already looks for the device, so the
  cap adds no scan. The constant lives in `device_limits.hpp` because `auth_service.cpp` has no `ClientApiLimits`.
* **Name length: 400 `M_TOO_LARGE`.** `POST /login`, `POST /register` and `PUT /devices/{deviceId}` refuse a name over
  `ClientApiLimits::max_device_display_name_bytes` (256) before anything is written. The status matches the other per-user
  caps, and the name is the client's input, so 400. Bytes, not code points, because storage and the EDU are in bytes.
* **Refuse, do not evict.** Evicting the oldest device at the cap would sign a user's other session out, and anyone who
  logs in with a stolen password could use it to log the owner out of every client. A refused login costs the owner a
  deliberate device deletion.
* **Refuse, do not truncate.** A silently shortened name differs from what the client sent and what it will display; a
  clear error lets the client choose.
* **Linear announcement.** `build_device_list_update_batch` builds one `DeviceDisplayNames` and one index of the user's
  device keys and makes the EDU content for every device from them. `PersistentStore::device_table_rows_examined`
  counts the rows of both tables where they are read, so a test can prove the cost without timing and can show that
  the per-device path reads far more. Each entry equals what `build_device_list_update_content` returns for the same
  device, byte for byte.

### Positive Consequences

* Announcing a user's devices is a fixed number of passes over the device tables plus work per device. That work
  includes merging the signatures on the device's keys, which reads the rows naming this user through the per-target
  index, once per device.
* A user's device rows, and every scan keyed by user, are bounded.

### Negative Consequences

* A user with 200 devices must delete one before signing in on a new one.
* The two limits are not configuration keys.

## Pros and Cons of the Options

### Evict the oldest device at the cap

* Good, because a login never fails.
* Bad, because someone with the password signs the owner out of their oldest sessions, and room keys held only by that device are lost.

### Truncate a long name

* Good, because a login with a long name still succeeds.
* Bad, because the stored name is not what the client sent, and a cut can split a multi-byte character.

### Only make the announcement linear

* Good, because it needs no refusal.
* Bad, because the stored rows, every other scan of the device table and every per-user list stay unbounded.

### Make the caps configuration keys

* Good, because an operator could raise them.
* Bad, because the device cap sits in a function with no access to the client API limits, and a key adds a reload and validation surface for a number no deployment needs to change; a key can be added later without changing the behaviour.
