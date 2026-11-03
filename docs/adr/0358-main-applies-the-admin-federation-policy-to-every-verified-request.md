# Main applies the admin's federation policy to every verified request, and again to what a worker relays

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-21 (`fed.policy-rules-not-enforced-on-worker-routed-requests`)

## Context and Problem Statement

An admin can deny or quarantine a federation peer with a scope-`federation` policy rule. The rule was looked up
only in `handle_federation_http_request`, in the process-local `PersistentStore`. In production
`FederationProxy::handle` verifies the X-Matrix signature in main and forwards nearly every request to a worker,
whose store holds no rules on PostgreSQL (`policy_rules` is not in `federation_worker_table_allowlist`) and a
start-up snapshot on SQLite. A denied origin therefore kept federating, and the main-side relay handlers
(`pdu_ingest`, `membership_ingest`, `invite_ingest`, `edu_ingest`) never asked about rules either. Where is the
decision made, so that it holds from the moment the rule exists?

## Decision Drivers

* The worker is the process most exposed to hostile input and is assumed compromisable; its snapshot of anything
  that changes after it starts is stale by construction.
* The policy server (`security.trust_safety.policy_server_url`) is an external call that must not run once per PDU.
* A request must not ask the policy server twice, whichever process answers it.

## Considered Options

* Push the rules to the workers, and evaluate them there
* Have the worker ask main for each decision over IPC
* Decide in main in `FederationProxy::handle`, and judge relays again in main

## Decision Outcome

Chosen option: "decide in main", because it is the only place that sees every rule change at once and the only
one a compromised worker cannot skip.

* `evaluate_inbound_federation_policy(runtime, origin, consult_policy_server)` reads the rule under
  `runtime.mutex` and asks the policy server (when asked to) with the mutex released, as `handle_federation_http_request`
  did.
* `FederationProxy::handle` applies the rule (no policy server) to the verified origin after
  `verify_inbound_federation_signature` succeeds and before every branch, including the forward to a worker. A denied or
  quarantined origin gets `403 M_FORBIDDEN`.
* The policy server is asked once, where the request is handed on: by the proxy just before it forwards to a worker (it
  reads the rule again then), and by `handle_federation_http_request` for what main answers itself (duplicate
  transaction, EDU-only `/send`, a room whose reload failed, discovery endpoints). A worker never asks:
  `HomeserverRuntime::federation_policy_decided_upstream` is set in the worker, so `handle_federation_http_request` skips
  the decision there, and the worker's sandbox is not asked to resolve or connect anywhere for it (ADR-0361).
* The main-side relay handlers judge the local rule again for the transport origin, without the policy server, so a
  rule added while a request was in flight still holds. `edu_ingest` does so for the origin main authenticated for the
  parent request; the other three use the origin the worker names, which is as trustworthy as the worker.

### Positive Consequences

* A rule takes effect on the next request and on the next relay, on either database backend.
* One policy-server round trip per request, as before.

### Negative Consequences

* The origin named in a `pdu_ingest`, `membership_ingest` or `invite_ingest` frame is the worker's claim. A
  compromised worker can name an allowed origin; it can already relay any event whose signatures verify, and the
  room ACL check on the signed sender (ADR-0359) does not depend on the claim.

## Pros and Cons of the Options

### Push the rules to the workers

* Bad, because it needs a new frame, an ordering guarantee against in-flight requests, and still trusts the worker to apply it.

### Have the worker ask main per decision

* Bad, because a round trip on every request and relay for a decision main can make before forwarding.

## Links

* Related to [ADR-0359](0359-main-judges-relayed-events-against-its-own-server-acl.md) and
  [ADR-0361](0361-the-policy-server-is-an-operator-trusted-destination-resolved-in-the-hook-and-admitted-through-a-budget.md)
