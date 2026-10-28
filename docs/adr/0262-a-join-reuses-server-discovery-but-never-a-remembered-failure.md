# A join reuses server discovery but never a remembered failure

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A6)

## Context and Problem Statement

`make_join` and `send_join` each ran the whole `.well-known`, SRV and DNS cascade, adding latency to every federated join. Other callers already use the 60 s `CachedServerDiscovery`, which also caches failures.

## Considered Options

* Use the cache with `DiscoveryCachePolicy::successes_only`
* Use the cache with remembered failures
* Keep resolving on every call

## Decision Outcome

Chosen option: "Use the cache with `DiscoveryCachePolicy::successes_only`", because a join is usually a person retrying by hand after a server recovers, and a remembered failure would refuse it for up to 60 s. The spec says discovery results "should be cached". The cache is used only while it wraps `runtime.discovery_network` (compared by address), so a test that swaps the network never leaves it holding a dangling reference.

### Positive Consequences

* One cascade per join pair per minute.

### Negative Consequences

* A failing destination is re-resolved on every join attempt.
