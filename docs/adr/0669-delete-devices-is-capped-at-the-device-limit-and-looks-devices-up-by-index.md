# POST /delete_devices is capped at the device limit and looks devices up through indexes

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C02, one `delete_devices` request holding `runtime.mutex` for entries x (devices + sessions)

## Context and Problem Statement

`POST /delete_devices` took a `devices` array of any length (about 260,000 one-character IDs fit in the 1 MiB body) and called
`delete_local_device` for each. That function scanned the whole `persistent_store.devices` vector and the whole session table
for every ID, even for an ID that is not the caller's, all under `runtime.mutex`. How is the work bounded by the caller's own
devices instead of by the list they send?

## Decision Drivers

* No work under `runtime.mutex` grows with what a low-trust account chooses (ADR-0603).
* A client never has a reason to name more devices than an account may hold.
* `DELETE /devices/{deviceId}` shares `delete_local_device` and had the same scans.

## Considered Options

* Refuse a list longer than `device_count_limit`, de-duplicate, and make `delete_local_device` index-based
* Keep accepting any length, but collect the caller's device IDs once and skip the others in the handler
* Bound the lock hold with a time budget inside the loop

## Decision Outcome

Chosen option: "Refuse a list longer than `device_count_limit`, de-duplicate, and make `delete_local_device` index-based".

A list over `device_count_limit` (200) entries is `400 M_INVALID_PARAM` before the password check, with nothing deleted. The
count is of the entries sent, repeats included, so a body cannot be padded with copies. Repeats within the list are then
handled once. `delete_local_device` finds the device row with `database::has_user_device` (the user's own rows through
`device_user_index`, ADR-0603) and revokes sessions with `SessionTable::revoke_device` (the (user, device) index of F-08), so
an absent ID costs the caller's device rows and no session. The same functions serve `DELETE /devices/{deviceId}` and the
refresh path's device check.

### Rejected: filtering in the handler and keeping any length

It would leave 260,000 lookups per request, each cheap but still linear in a number the caller picks, and the other callers of
`delete_local_device` would keep their scans. The cap and the indexed lookup are both needed: the index alone leaves the loop
long, the cap alone leaves each iteration linear in the server.

### Rejected: a time budget in the loop

A budget would answer a legitimate request half done and make the result depend on server load. The cap makes the work a
function of the request alone.

### Negative Consequences

* A client that sends more than 200 IDs gets a 400 instead of a 200. No account can hold that many devices, so no honest
  client does.
* `delete_device` still erases the row from the ordered `devices` vector and rebuilds `device_user_index`, which is linear in
  the table, once per device that really exists (at most 200 per request).
