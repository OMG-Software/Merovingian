# Outbound delivery never serves a remembered discovery failure

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestToDeviceMessagesOverFederation/stopped_server`, failing since 0.12.90 or earlier.

## Context and Problem Statement

`runtime.cached_discovery` caches server discovery for 60 seconds, including failures, so that a failing server does
not cost a full `.well-known`, SRV and DNS cascade on every PDU of a large inbound transaction. The dispatch worker's
resolver used the cache's default policy, `remember_failures`.

In the failing test, hs1 queues a to-device EDU for hs2 while hs2 is down, and hs1 is then restarted. On restart hs1
replays the transaction at once. hs2 is still down, so discovery fails and the failure is cached. hs2 comes back five
seconds later. hs1's next retries, at about 8 and then 24 seconds, are answered from the cached failure without
asking the network, so the backoff doubles each time and the next attempt lands after the test's 30-second wait. The
transaction itself was durable and replayed, and nothing dropped it.

Which cached discovery answers may outbound delivery use?

## Decision Drivers

* The dispatch worker already paces a failing destination. A destination that is backing off takes no thread and no
  lookup (`destination_should_retry`), so a remembered failure saves nothing the backoff does not.
* A retry after the destination recovers must reach it, as for a client's join (ADR-0262).
* A success is still worth reusing: every transaction to a reachable peer would otherwise repeat the cascade.

## Considered Options

* The dispatch resolver uses `DiscoveryCachePolicy::successes_only`: a fresh success is reused, a remembered failure
  is ignored and the network is asked again.
* Shorten the cache's lifetime for failures only.
* Clear a destination's cached failure when that server sends this server a request.

## Decision Outcome

Chosen option: the first. `federation::make_dispatch_resolver` builds the resolver `wire_federation_callbacks` gives
the worker. It asks `cached_discovery` with `successes_only`, or the raw network when there is no cache. What it
finds still replaces the cache entry for every other caller, as `CachedServerDiscovery::discover` does for any policy.
Key resolution, pushers and appservices keep `remember_failures`.

### Positive Consequences

* Delivery to a destination resumes at its first retry after the destination recovers.
* A sender's restart while a peer is down no longer loses the first minute of the peer's recovery.

### Negative Consequences

* A destination that stays down is looked up once per backoff step, every few seconds at first and every 300 s at
  the cap, instead of once a minute. Each lookup is bounded by `dispatch_discovery_timeout_seconds` (10 s, ADR-0354).

## Pros and Cons of the Options

### A shorter lifetime for failures

* Good, because every caller benefits.
* Bad, because it changes the cache for key resolution, where remembering a failure guards against a request flood,
  and any lifetime still refuses a retry that falls inside it.

### Clear a cached failure when the destination sends a request

* Good, because it reacts to evidence that the peer is up.
* Bad, because an inbound origin is not proven until its signature verifies, so an unverified request could change
  outbound behaviour. Many recovered peers also never send this server anything.

## Links

* Applies [ADR-0262](0262-a-join-reuses-server-discovery-but-never-a-remembered-failure.md) to outbound delivery
* Bounded by [ADR-0354](0354-federation-delivery-gives-each-destination-at-most-one-thread.md)
