# Remote device lists are cached in memory for users who share a room, and filled from GET /user/devices

* Status: accepted
* Date: 2026-11-07

Technical Story: project analysis, finding G14 ("remote device-list cache"); `docs/todos/capability-gaps.md`.

## Context and Problem Statement

Before this change every `POST /keys/query` naming a remote user asked that user's server with
`POST /_matrix/federation/v1/user/keys/query`, and an inbound `m.device_list_update` only put the user in the
local observers' `device_lists.changed`. The spec (SS API, "Device Management") says a server "should populate a local
cache" and apply later updates to it. Without one, every client of every local user who shares a room with a remote
user re-asks the remote server after every change, an unreachable server makes the user's devices vanish from every
answer, and an update that changes nothing is still reported to every client.

What should be cached, for whom, where, and from which request is it filled?

## Decision Drivers

* An entry is only correct while updates reach this server, and a server sends updates only to the servers that share
  a room with the user.
* Everything is done under `runtime.mutex`, on lists a remote server chooses: the work and the memory must be bounded.
* A cache must never serve half a list or another user's keys.

## Considered Options

* Cache in memory, only users who share a joined room with a local user, filled from `GET /user/devices/{userId}`.
* Fill from the `POST /user/keys/query` answer the query already makes.
* Persist the cache in a database table.

## Decision Outcome

Chosen option: an in-memory `federation::RemoteDeviceListCache` on `HomeserverRuntime` (`remote_device_lists`,
guarded by `runtime.mutex`), holding only remote users who share a joined room with a local user
(`remote_users_sharing_a_room_with_local_users`), filled from `GET /user/devices/{userId}`.

* `/user/keys/query` has no `stream_id`, so updates could never be placed against a list filled from it. The spec
  names `/user/devices` as the answer whose `stream_id` "is matched with the stream_id field in m.device_list_update
  EDUs". A fill is at most 4 users per `/keys/query` request, inside the request's one ADR-0079 slot, one admitted
  server and one deadline, `OutboundAnswerTrust::unverified` (label `key_query.user_devices`). A failed fill or a
  refused answer falls back to the batched `/user/keys/query` for that user.
* The answer is accepted whole or not at all (`accept_remote_user_devices_response`): every device filed under the
  asked user and its own ID, cross-signing keys valid for the user and usage, the remote `unsigned` dropped.
* A user outside the shared-room scope is erased when a query or update names them, and when they leave the last
  room they share with a local user (`record_room_share_ended_device_changes`). A local user leaving is not
  tracked per remote member: the entry goes at the next query or update that names the user, and the caps bound
  what waits until then. The cached master key still gets the viewer's own uploaded
  signatures merged in (`merge_visible_key_signatures`), exactly as an answer from the remote server does.
* Not persisted: a restart starts empty and fills on demand. A table would need a migration and a way to know that
  updates sent while this server was down were not missed, which it cannot know.

### Positive Consequences

* A second `/keys/query` for a cached user makes no remote call and survives the remote server being down.
* An update that changes nothing is not reported to clients again (ADR-0561).

### Negative Consequences

* A cached list is only as current as the updates the remote server sends; a lost update is noticed only when a later
  one names it in `prev_id`.
* Complement's `TestDeviceListsUpdateOverFederation` entries stay in the skip list until it is run against this
  change.

## Links

* Refined by [ADR-0561](0561-device-list-updates-apply-in-stream-order-a-gap-marks-the-list-stale-and-the-cache-is-bounded.md)
* [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md), [ADR-0349](0349-an-outbound-answer-main-does-not-verify-comes-over-mains-own-connection.md), [ADR-0350](0350-a-key-query-or-claim-takes-one-slot-one-deadline-and-asks-a-bounded-number-of-servers.md)
