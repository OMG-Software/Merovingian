# Main re-verifies PDUs relayed by the federation worker

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-27

Technical Story: 0.12.13 security branch, decision D2 in
`docs/todos/audit-0.12.13-handover.md`; threat-model entry #450.

## Context and Problem Statement

The federation worker verifies each inbound PDU's signature and then relays it
to main over IPC (`pdu_ingest` for `/send`, `membership_ingest` for
send_join/leave/knock, `invite_ingest` for invites). Main persisted what the
worker relayed without checking the signature itself. The worker holds no
signing secret (ADR-0015, ADR-0062), but a compromised worker could still make
main persist events impersonating any sender the room's state authorises. The
IPC frame also carries the envelope fields (`sender`, `event_id`,
`state_key`, event ID lists) separately from the signed event JSON, so even a
signature check on the JSON alone would leave those fields on the worker's
word.

How should main decide that a relayed PDU is genuine?

## Decision Drivers

* Spec, server-server-api.md "Checks performed on receipt of a PDU", step 2:
  an event that fails signature checks is dropped.
* The worker is the process most exposed to hostile input; main holds the
  signing secret and owns the authoritative store.
* `src/homeserver/AGENTS.md`: never hold `runtime.mutex` across a network
  call. Resolving a key may fetch it.

## Considered Options

* **Main resolves the key itself (chosen).** Main verifies with its own
  `remote_key_resolver`: cache first, a network fetch on a miss, with no
  runtime lock held.
* **Main's cache only.** No network fetch; a cache miss is refused as
  retryable. Simpler, but a key main has not cached yet stalls federation
  from that server until something else fetches it.
* **The worker passes the key it verified with.** Rejected: a compromised
  worker would supply both the key and the signature, so the check proves
  nothing.
* **Keep trusting the worker.** The accepted-risk position before 0.12.13.

## Decision Outcome

Chosen option: "Main resolves the key itself", because it is the only option
under which a compromised worker cannot get a forged PDU persisted and
federation keeps working when main's cache is cold.

* `handle_pdu_ingest_request`, `handle_membership_ingest_request` and
  `handle_invite_ingest_request` (`src/homeserver/worker_pool.cpp`) run
  `federation::authorize_federation_pdu`, the check the worker runs, with a
  key from main's `remote_key_resolver`, before taking `runtime.mutex`.
* The room version is the one main records for the room; the worker's claim
  is used only for a room main does not hold (an invite to a remote room).
* The `/send` and membership envelopes are rebuilt from the verified event
  JSON; a frame whose event ID or room ID disagrees with the signed event is
  refused. For invites, whose handler reads the event JSON itself, the
  frame's event ID must equal the one the signed event hashes to.
* The worker's PostgreSQL role cannot write the key cache (ADR-0062), so a
  key main uses is one main fetched or cached itself.

This required the signing-key cache to be safe for concurrent use: the
resolver now runs on main's relay threads as well as in backfill, both
without the runtime lock. `PersistentStore::server_signing_keys` is guarded by
its own mutex, and iterating callers use `snapshot_server_signing_keys`.

### Positive Consequences

* A compromised or buggy worker cannot get a forged PDU persisted by main.
* The worker's framed envelope fields are no longer trusted.

### Negative Consequences

* A cache miss makes main fetch the sender server's keys, as the worker has
  already done: one more outbound request per new key.
* The frame's transport `origin` is still the worker's claim. It only chooses
  where main backfills from, and everything fetched there is verified again.

## Links

* Supersedes the #450 accepted-risk entry in `docs/threat-model.md`
* [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
* Tests: `tests/integration/test_worker_relay_signature_flow.cpp`
  (`[worker_relay_signature]`); `tests/unit/test_database_persistence.cpp`
  (`[signing-key][concurrency]`)
