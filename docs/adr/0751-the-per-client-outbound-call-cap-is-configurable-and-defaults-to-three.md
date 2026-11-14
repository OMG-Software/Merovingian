# The per-client outbound call cap is configurable and defaults to three

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestFederationRoomsInvite` and `TestJumpToDateEndpoint` subtests answered
`429 M_LIMIT_EXCEEDED` on `POST /join` since 0.12.92

## Context and Problem Statement

[ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) bounds the
client-triggered calls this server makes to other servers: half of the request pool in total, and one per client
address, keyed by `rate_limit_client_key`. [ADR-0622](0622-a-clients-federated-join-knock-or-leave-holds-a-client-outbound-slot.md)
added federated joins, knocks and leaves to that budget, taken at once or answered 429.

With one call per address, one client joining two remote rooms at once, or two users behind one NAT address doing
so, has every call but the first refused. Complement sends every request from one address and does not retry a 429,
so its parallel subtests' remote joins refused each other: 0 hits in the run before the audit, 3 to 5 in every run
since. The spec lists 429 for `POST /join`, so the server is not wrong, but one call per address is tighter than the
threat needs. How many calls may one address have in flight, and who decides?

## Decision Drivers

* ADR-0079's threat: a client naming a peer that never answers must not pin the request pool. The global cap of half
  the pool is what keeps the other half free.
* The per-client cap stops one address from taking the whole global budget.
* Legitimate clients do more than one remote call at once, and addresses are shared.

## Considered Options

* `server.http.client_outbound_max_per_client`, default 3, clamped to the global cap.
* Keep one per address, and record the Complement subtests as expected failures.
* Let a federated join, knock or leave wait for its client's slot (the ADR-0306 form).

## Decision Outcome

Chosen option: the configuration key, default 3. The owner chose the default.

* `server.http.client_outbound_max_per_client`, 1..128, restart required. `client_outbound_proxy_policy_for_pool`
  clamps it to the global cap (`request_threads / 2`, at least 1), so it can never exceed what the pool can spare.
* The global cap is unchanged, so the pool still keeps half of its threads for requests that never leave the server.
* Every route that takes a client-outbound slot uses the same cap: directory, alias, profile and key lookups, remote
  media without the fetch pool, the hierarchy walk, `timestamp_to_event`, remote invites, and federated joins, knocks
  and leaves.
* Complement's image sets 16, the global cap of the default pool, because it sends every request from one address.

### Positive Consequences

* A client can join a remote room while it looks another one up, and a small office behind one address is not limited
  to one remote call at a time.
* An operator whose users share an address without a `server.trusted_proxies` entry can raise it.

### Negative Consequences

* One address may now hold three slots of the global budget instead of one, so it takes more addresses to fill the
  budget with calls to a peer that never answers. The global cap, the deadlines and the per-address connection share
  (ADR-0072) still bound it.

## Pros and Cons of the Options

### Keep one per address, and record the subtests as expected failures

* Bad, because which subtests fail depends on timing, so the entries would flap between failing and stale.
* Bad, because it keeps real clients' second concurrent remote call refused.

### Let a join, knock or leave wait for its client's slot

* Bad, because ADR-0622 rejected it: a waiter holds a request thread as well.

## Links

* Amends [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) (the per-client
  cap of one)
* Relates to [ADR-0622](0622-a-clients-federated-join-knock-or-leave-holds-a-client-outbound-slot.md)
