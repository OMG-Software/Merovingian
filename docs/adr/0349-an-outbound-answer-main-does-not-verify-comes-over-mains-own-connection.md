# An outbound federation answer main does not verify comes over main's own connection

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-43 (`fed.outbound-tunnel-worker-forges-unsigned-remote-responses`)

## Context and Problem Statement

Main signs every outbound federation request itself (ADR-0078: the worker never signs). Until now it then handed the
signed request to the sandboxed federation worker whenever federation was enabled
(`FederationProxy::send_outbound_request`, the `outbound_http_request` frame), and took `ok`, the HTTP status, the body
and `error_detail` of the `outbound_http_response` frame as the destination's answer. The worker is the process most
exposed to hostile traffic (it parses every inbound federation request), and the project treats its compromise as
realistic. Where the answer carries a signature main checks, a forged frame buys nothing. Where it does not, a
compromised worker could speak as any remote server to main: forged device and cross-signing keys and one-time keys
reached clients, forged alias and public-room answers reached clients and steered `POST /join/{alias}`, a forged 403 to
`make_leave` ended an invite locally, and a forged `send_leave` or `send_knock` success recorded a membership nothing
delivered. Signed objects were never at risk: main's key resolver and `DispatchWorker` already use main's own
`OutboundClient`.

Which outbound calls may still be carried by the worker, and what does the worker's reply have to satisfy first?

## Decision Drivers

* A frame from the worker is input, not a fact (`src/homeserver/AGENTS.md`, "Federation worker relays are untrusted
  input"; ADR-0071 for relayed PDUs; ADR-0078).
* The worker must hold no capability whose abuse is worse than what it can already do (ADR-0078).
* Main already makes direct outbound HTTPS calls to remote servers (key fetches, `DispatchWorker`, remote media, server
  discovery), so the direct route adds no new kind of parsing.
* Do not leave a half-trusted route: a call that uses part of an answer unverified is unverified.

## Considered Options

* Route by trust: every caller says whether main verifies a signature on the whole answer; only those that do may use
  the worker
* Keep the tunnel for everything and record the residual
* Make the worker an opaque byte relay, with TLS and parsing in main
* Remove the tunnel, sending every call over main's own client

## Decision Outcome

Chosen option: "route by trust". `perform_outbound_call` and its three wrappers take a required
`OutboundAnswerTrust`. `unverified` (the answer is main's to act on as given) goes over `runtime.outbound_client`;
`signature_verified` goes through `FederationProxy` when one is wired. There is no default, so a new caller has to
choose, and `tests/tooling/test_outbound_answer_trust.py` pins the table below: it fails if a caller is added, removed
or reclassified without this ADR changing.

A call is `signature_verified` only if every use main makes of a success body is a signature check on the whole of it,
and a failure only means "no data". A status that main acts on (a 403 that ends an invite, a 4xx that is a final
refusal), a template main keeps, or a choice among signed objects that nothing signs as a whole, makes the call
`unverified`. That is why `send_join` (the signed state is verified event by event, but which events are sent, and the
status, are not) and the invite (the answer is verified, a 4xx is acted on) are `unverified` although they carry
signed material.

| Caller (diagnostic event) | What main does with the answer | Signature on the whole answer | Route |
|---|---|---|---|
| `key_query.remote` | returns device, master and self-signing keys to the client | no (only filtered to the users asked) | direct |
| `key_claim.remote` | returns one-time keys to the client | no | direct |
| `profile.proxy` | relays `displayname`, `avatar_url`, and the remote's 403/404 | no | direct |
| `public_rooms.proxy` | relays the room chunk | no | direct |
| `directory.room.proxy` | relays the room ID and servers | no | direct |
| `room.join.alias_lookup_failed` | joins the room ID and via servers the answer names | no | direct |
| `federation.backfill.state_ids_failed` | the IDs name the state a later event is judged against | no (the PDUs they lead to are verified, the choice of IDs is not) | direct |
| `timestamp_to_event.ask` | the event ID and timestamp decide which event is offered | no (the event is verified, the choice is not) | direct |
| `space_hierarchy.fetch` | room summaries shown to the client | no | direct |
| `room.join.remote.make_join_failed` | keeps the template's `prev_events`, `auth_events`, `depth`, content | no | direct |
| `room.join.remote.send_join_failed` | state and auth chain, and the status | per event only | direct |
| `room.leave.remote.make_leave_failed` | template; a 403/404 ends an invite locally | no | direct |
| `room.leave.remote.send_leave_failed` | success commits the local leave | no | direct |
| `room.invite.remote_failed` | co-signed event; a 4xx is a final refusal | success only | direct |
| `room.knock.remote.make_knock_failed` | keeps the template | no | direct |
| `room.knock.remote.send_knock_failed` | success records the knock | no | direct |
| `federation.backfill.get_missing_events_failed` | each PDU verified (signature, hash, auth) before it is stored | yes | worker |
| `federation.backfill.event_fetch_failed` | the PDU is verified before it is stored | yes | worker |
| `federation.backfill.snapshot_event_fetch_failed` | the PDU is verified before it is stored | yes | worker |
| `federation.backfill.event_auth_failed` | every PDU of the chain is verified before it is stored | yes | worker |

The tunnel therefore stays, for the four backfill fetches. They are the calls with the largest bodies
(`backfill_response_max_bytes`), so keeping the TLS and HTTP parsing of those in the sandboxed worker keeps most remote
bytes out of main. What a compromised worker can do to them is what it could always do: withhold a PDU or replay one a
server signed.

For whatever stays on the tunnel, `WorkerPool::send_outbound_request` now checks the reply before using it
(`validate_worker_outbound_reply`): a success needs an HTTP status in 100 to 599 and a body no larger than the
request's `max_response_body_bytes`; a failure carries no status and no body; `error_detail` is cut to 256 bytes with
control and non-ASCII bytes replaced, because it reaches log lines and client-visible error text.

The direct route has the protections the tunnel had, because both end in the same `OutboundClient::perform` on the
same signed `OutboundRequest`: the destination is resolved through `federation::discover_server` (SSRF policy) and
pinned with `CURLOPT_RESOLVE`; TLS is verified against the discovered `tls_server_name`; the response is capped by
`max_response_body_bytes`; the deadline is the caller's (`OutboundDeadline` for client-triggered calls); and
`runtime.mutex` is released for discovery and for the exchange (`RuntimeLockRelease`). Main's seccomp allowlist already
admits the syscalls of that path, since main makes the same calls for key fetches, `DispatchWorker` and remote media.
Main now parses more remote responses itself, in the same libcurl and JSON code it already uses on remote key and
media answers; `docs/threat-model.md` and `docs/hardening.md` record that.

### Positive Consequences

* A compromised worker can no longer make main believe an unsigned answer, whichever remote server it names.
* Adding an outbound call forces a trust decision and a table row.

### Negative Consequences

* A request handler thread of main now carries the TLS exchange of the 16 direct calls, not only the wait for the
  worker's reply. It was blocked either way (the IPC wait held the same thread), so the pool's occupancy is unchanged.
* More remote response bytes are parsed in the unsandboxed main process.
* Residual, not fixed here: inbound `fed_response` frames reach remote peers from the worker unchanged, so a compromised
  worker can still lie to other servers about this server's users. That is the other direction and out of scope for this
  decision.

## Pros and Cons of the Options

### Keep the tunnel for everything and record the residual

* Good, because it changes nothing
* Bad, because forged unsigned answers reach clients and decide local membership state, and the rule that the worker holds
  no capability worse than what it already has (ADR-0078) is not met

### Make the worker an opaque byte relay, with TLS and parsing in main

* Good, because the worker would see only ciphertext
* Bad, because main would terminate TLS itself, which is the direct route plus an IPC hop, with no gain

### Remove the tunnel, sending every call over main's own client

* Good, because there is one route and no table
* Bad, because the largest remote bodies would then be parsed in main as well, for no gain: their content is verified
  object by object whichever process carried it

## Links

* Refines [ADR-0078](0078-the-federation-worker-never-signs.md): the worker's replies are input as its requests are
* Relates to [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
* Relates to [ADR-0350](0350-a-key-query-or-claim-takes-one-slot-one-deadline-and-asks-a-bounded-number-of-servers.md): the same call sites
