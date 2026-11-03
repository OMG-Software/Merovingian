# A key query or claim takes one slot, one deadline and asks a bounded number of servers

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-17 (`fed.client-outbound-keys-query-claim-join-alias-unslotted-serial`)

## Context and Problem Statement

`POST /keys/query` and `POST /keys/claim` group the requested users by server and called each remote server in turn on
the request thread, each with the full `remote_timeout` (60 s by default), with no ADR-0079 slot, no shared deadline and
no cap on the number of distinct servers. One body naming many servers that accept a connection and never answer held a
main-pool thread for the sum of their timeouts; a few client addresses could pin the whole pool. `POST /join/{#alias}`
made the same unslotted, 60 s remote alias lookup that ADR-0079 explicitly puts under the budget. How should these
routes be bounded, given that `/keys/claim` consumes local one-time keys before it asks anyone else?

## Decision Drivers

* ADR-0079: every client-triggered outbound call takes a slot before it releases the runtime lock, and keeps it until the
  call has ended; discovery and requests draw from one deadline.
* The spec's `failures` object exists for "remote homeservers [that] could not be reached" in both routes
  (client-server-api.md, `POST /keys/query` and `POST /keys/claim`), so a refused server has a place in the answer.
* A claimed one-time key is deleted from the store; an answer that is refused after that loses it.

## Considered Options

* One slot per request, taken before the remote loop; one `OutboundDeadline` for all remote calls; at most
  `remote_keys_max_servers` distinct servers; every server not asked is reported in `failures`
* Answer `429 M_LIMIT_EXCEEDED` for the whole request when no slot is free
* Call the remote servers in parallel
* One slot per remote server

## Decision Outcome

Chosen option: "one slot per request, one deadline, a server cap, refusals in `failures`".

* `RemoteKeyCalls` (client_server.cpp) takes the slot with `admit_client_outbound_proxy` before the remote loop, keyed
  by `rate_limit_client_key`, and holds it until the loop ends. Without a slot, every remote server is reported in
  `failures` with `M_LIMIT_EXCEEDED`; nothing is dialled.
* Every remote call runs through `perform_bounded_outbound_call` with `OutboundDeadline::remaining_seconds()`, so discovery
  and each request draw from one budget, `remote_keys_deadline_seconds` (30 s, lowered to `remote_timeout`). A server
  reached after the budget is spent fails as "deadline exceeded" without being dialled.
* At most `remote_keys_max_servers` (16) distinct servers are asked per request; the rest are reported in `failures` with
  `M_LIMIT_EXCEEDED` and "too many remote servers in one request".
* The remote half runs after the local half, so a refusal never loses a one-time key: the keys already claimed here are
  in the answer. This ordering is why a refusal is a `failures` entry and not a 429 for the request.
* `POST /join/{#alias}` with a remote alias takes a slot (`429 M_LIMIT_EXCEEDED` when none is free, as the sibling
  `GET /directory/room/{alias}` does) and runs under the directory deadline.
* The two policy values live in `ClientOutboundProxyPolicy` beside the other ADR-0079 values and have no configuration
  of their own.

### Positive Consequences

* The thread time of one key request is bounded by `remote_keys_deadline_seconds`, whatever the body names.
* A busy server still serves the local part of a key request.

### Negative Consequences

* With one slot per client address (`per_client_cap`), a second concurrent key request that names remote servers from
  the same address sees those servers as failures and the client must retry. Clients retry `failures` on the next query.
* The deadline is shared, so a slow first server can starve the servers after it of time; they are reported as failures.

## Pros and Cons of the Options

### Answer `429` for the whole request when no slot is free

* Good, because it is what the unauthenticated proxies do
* Bad, because for `/keys/claim` the one-time keys are already consumed, so a 429 would lose them, and the spec has a
  place for exactly this in `failures`

### Call the remote servers in parallel

* Good, because the deadline would not starve later servers
* Bad, because one request would hold many threads, which is the exhaustion this decision closes

### One slot per remote server

* Good, because each call is accounted for
* Bad, because a body naming sixteen servers would need sixteen slots from a budget with a per-client cap of one, so no
  request naming more than one server could succeed

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* Relates to [ADR-0349](0349-an-outbound-answer-main-does-not-verify-comes-over-mains-own-connection.md): the same call sites
