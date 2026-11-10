# Bind worker key-claim and key/profile query relays to the verified request by digest

* Status: accepted
* Date: 2026-11-10

Technical Story: GHSA-3p5v-vrg8-f545 (internal adversarial audit run-1, unbound one-time-key claim IPC relay)

## Context and Problem Statement

A federation worker serves `POST /user/keys/claim`, `POST /user/keys/query`, `GET /user/devices/{userId}` and
`GET /query/profile` by relaying the call to main (`otk_claim_ingest`, `device_keys_query_ingest`, `user_devices_ingest`,
`profile_query_ingest`), because its own store is a start-up snapshot. Main ran each relay on whatever the frame said.
The worker's PostgreSQL role is denied `one_time_keys`, `devices`, `device_keys` and `profiles` (ADR-0062), so these four
frames were a way round that boundary: a compromised worker could claim, and so delete, every one-time key of every
local device at will, and read any local user's devices, keys and profile without a remote server asking. How should
main decide whether a relay of this kind is one a real federation request caused?

## Decision Drivers

* The worker is the process most exposed to hostile input; a frame from it is untrusted (ADR-0071, ADR-0078).
* A one-time-key claim is a write: each key claimed is removed. Olm depends on a key being used once.
* The F-74 EDU binding (ADR-0395) already gives a pending request main-owned permits, consumed once, under the pending
  lock, with liveness and origin checks. A second mechanism would be a second thing to get wrong.
* Main and the worker must read the same argument out of the request, or a genuine relay is refused.

## Considered Options

* Per-request permits: `WorkerPool::handle` gives a signature-verified request one digest of the argument its route
  may relay; main admits a relay only by consuming an equal unused digest on the parent named in the frame.
* Origin correlation only: admit a relay that names a live verified parent, as FED-12 did for EDUs (ADR-0142).
* Take these routes out of the worker and answer them in main.
* Grant the worker's role the tables and let it answer from the database.

## Decision Outcome

Chosen option: per-request permits, because it binds each relay to bytes main authenticated, at a cost of one hash and
a short scan, and reuses the F-74 machinery.

`federation::verified_request_relay_digests(method, target, body)` gives the permits: one for a claim or keys query
(the body), a device list (the user ID in the path) or a profile query (the `user_id` parameter), none for any other
route. `WorkerPool::handle` passes them to `IpcChannel::send_request` only when main verified the request's signature.
The worker's four relay frames carry `parent_request_id` from the request it is serving (`FedRequestParentScope`) and
the worker refuses to relay with none. Each main handler hashes the frame's argument with
`federation::worker_relay_digest` before taking `runtime.mutex`, then, under it, admits the relay only through
`IpcChannel::consume_pending_relay`: a live, healthy, verified parent on the receiving channel, before its deadline,
holding an unused equal digest, which is then marked used. A refusal is logged at warning level and answered with the
provider's empty answer.

The digest hashes `"relay:"`, the relay kind's name and the argument's length ahead of the argument, so a device-list
permit cannot be spent as a profile query, and no relay digest equals an EDU digest. The worker's federation handlers
read the argument with the same functions main uses (`core::query_parameter`, `user_devices_path_user_id`), so the
two cannot drift apart. The worker builds and sends the four frames only through `federation_worker::worker_relay_frame`
and `relay_to_main`, and main's relay scenarios run against frames built by the same function, so the frame tested is
the frame the worker sends.

Relays left unbound, and why:

* `pdu_ingest`, `membership_ingest`, `invite_ingest`: main re-verifies the event's signatures (ADR-0071).
* `edu_ingest`: bound by ADR-0395.
* `directory_query_ingest`, `public_rooms_ingest`, `event_query_ingest`, `membership_template_ingest`: they read only
  tables the worker's role may already read (`room_aliases`, `rooms`, `current_state`, `events`, the state tables), or
  public data; the event read keeps the origin-in-room gate and history-visibility filter in main. Binding them would
  protect nothing the worker cannot already reach.

### Positive Consequences

* A compromised worker can claim a one-time key only for a claim a remote server sent and main verified, once; it can
  read a device list, keys or a profile only for a query a remote server sent.
* The worker's database role and its IPC frames now enforce the same boundary.

### Negative Consequences

* Main and the worker must be upgraded together: a worker that sends no `parent_request_id` has every claim and query
  refused. They always are (one package, `WorkerSupervisor` spawns the worker from main's own install).
* A request whose argument the worker reads differently from main (it cannot, by construction) would be refused, not
  served wrongly.
* A compromised worker can still choose not to relay, or answer a remote server falsely. That is denial of service on
  the request it is serving, which it could always do.

## Pros and Cons of the Options

### Per-request permits

* Good, because a relay must match what the authenticated server asked for, byte for byte.
* Good, because permits share the F-74 lifetime rules: they die with the request.
* Bad, because main computes a hash per verified request of the four routes.

### Origin correlation only

* Good, because it is simpler: no digest.
* Bad, because one live verified request from any server, even a `/send`, would authorise any number of claims for any
  user. That is the attack.

### Answer these routes in main

* Good, because no relay exists to bind.
* Bad, because inbound federation is routed to the worker so that hostile traffic is parsed out of main; moving four
  routes back widens main's attack surface and puts their load on main's request pool.

### Grant the worker's role the tables

* Good, because the worker could answer without a relay.
* Bad, because a compromised worker could then delete one-time keys directly, and two processes deciding a claim is
  the split-brain the relay was added to remove.

## Links

* [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md): the worker's database role
* [ADR-0142](0142-bind-worker-edu-relays-to-live-main-verified-requests.md): origin correlation for EDU relays
* [ADR-0395](0395-bind-worker-edu-relays-to-the-edus-of-the-verified-body-by-digest.md): the digest binding this follows
* [Server-Server API, End-to-End Encryption](../matrix-v1.19-spec/server-server-api.md#end-to-end-encryption)
