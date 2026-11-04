# The operator's federation policy also covers the server that wrote an event

* Status: accepted
* Date: 2026-11-04

Technical Story: security audit run 2, finding F-72: `denied_servers`, `allowed_servers` and the admin
federation policy rules were checked against the request's origin only, so any other server could carry
events written by an excluded one, and this server fetched that server's signing keys to verify them.

## Context and Problem Statement

The Matrix spec says nothing about an operator's own list of servers. It is this project's control, so
how far it reaches is a decision, not a conformance question. The spec's room ACL is a different control,
and this decision does not change it.

A server in `denied_servers` is reachable through three doors the origin check never sees: a PDU relayed
in another server's `/send`, a fetched event during backfill or a missing-event fetch, and the state and
auth chain in a `send_join` answer. Each of them also resolved the excluded server's keys.

## Considered Options

* **Refuse the event on every ingest path, by the sender's domain, before fetching a key (chosen).**
* Keep the policy on the origin only and document it. Rejected: the operator's wish to have nothing to do
  with a server is defeated by any third server, and the key fetch still contacts the excluded server.
* Refuse only in `/send`. Rejected: backfill and `send_join` answers are the same content by another door.

## Decision Outcome

`operator_policy_refusal` (`src/federation/inbound_request.cpp`) answers for a server name, and these paths
ask it about the server of the event's `sender` before any key is resolved: `/send`, the worker relays
(`pdu_ingest`, `membership_ingest`, `invite_ingest`), `verify_and_store_backfilled_event` and
`filter_verified_send_join_events`. `remote_key_resolver` also refuses by config, so a path this list misses
still cannot contact an excluded server. The refused PDU gets a per-PDU error and costs its origin nothing,
because the origin may be an innocent relay.

The key resolver gate reads the config lists only, not the admin rules: a rule lookup needs `runtime.mutex`,
and key-resolution tasks must not wait on it. The admin rules are judged on the ingest paths above.

In a worker the provider answers nothing (`federation_policy_decided_upstream`), because main judges every
relay against its own store ([ADR-0358](0358-main-applies-the-admin-federation-policy-to-every-verified-request.md)):
a worker's copy of the rules can be stale, and refusing there would only move the decision away from the
process that holds them.

### Negative Consequences

* An event that descends from a refused event has a gap in its history here, like any missing event.
* In allow-list mode, a room created on a server that is not allowed cannot be joined, because its create
  event is refused.
* The lists are matched as exact strings, so `evil.org:8448` is a different name from `evil.org`. This was
  already true of the origin check; an operator has to list each form.

## Links

* Refined by [ADR-0391](0391-nothing-goes-out-to-a-server-the-operators-policy-excludes.md)
