# Separate cached verification keys from budgeted discovery

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

An authenticated relay can name many other sender domains in one transaction.
Resolving their PDU signing keys used the full peer resolver without the
source-address admission budget, runtime-wide in-flight cap or server/key
negative cache used for origin bootstrap (FED-10).

A persistent-key freshness hint is not proof that the full resolver avoids
network work: constructing a peer record can still require discovery. Conversely,
charging a genuinely local key read would reject cached verification or legitimate
known-peer key rotation when outbound resources are exhausted. A cache-served
origin lookup also must not release a reservation held by a different request.

## Decision Drivers

* Bound attacker-selected discovery and key-fetch work independently of the
  authenticated relay's identity and per-transaction parallelism.
* Preserve cached verification, retained local signing keys and known-peer rotation.
* Preserve discovery/trust validation for previously unknown origins.
* Make semaphore and admission ownership safe under resolver exceptions and
  asynchronous launch/unwind, without changing persisted or IPC formats.

## Considered Options

* Exempt the full resolver whenever a persistent signing key is fresh.
* Charge every key lookup, including local and persistent cache reads.
* Separate network-free verification-key reads from admitted peer resolution.

## Decision Outcome

Choose separate network-free verification-key reads and admitted peer resolution.
The production cache callback reads only owned local keys or fresh remote keys
from the persistent store. Its result is checked against the requested server/key
identity. PDU authorization still applies event-time validity and signature checks;
a key-only result does not establish a peer's discovery or trust state.

Relayed sender misses, including parallel pre-resolution and authorization
callbacks, use the existing source-address rate limit, shared in-flight cap and
bounded server/key failure cache. An admission rejection does not populate the
failure cache. Raw and IPC-verified router paths retain the client source used by
admission; empty sources still share the existing unknown bucket.

Known origins may replace their verification key directly from the cache while
retaining their established discovery/trust state. Unknown origins still require
an admitted full resolution. Production leaves the legacy full-resolution cache
hint unset; an embedded implementation may use it only when the entire resolution,
including discovery, is genuinely network-free.

Admission guards release only reservations they own. Parallel sender tasks move a
scheduling permit onto the invocation stack and capture the resolver by value,
so launch failure or resolver unwinding cannot strand permits or leave a dangling
callable reference. Futures are joined before their referenced result storage or
semaphore is destroyed.

### Positive Consequences

* A 50-distinct-sender regression stays within the configured resolution budget.
* Concurrent transactions share the actual runtime-wide cap, and cached lookups
  cannot release another transaction's reservation.
* Negative caching remains scoped to both server and key ID; cache hits remain
  usable with exhausted outbound budgets.
* Real database/router integration checks cover key ownership, freshness,
  source propagation, discovery admission and cached known-peer rotation.

### Negative Consequences

* A previously unknown origin with a fresh persistent key may still be throttled
  when discovery resources are exhausted. Key possession alone is insufficient
  to construct and validate its complete peer record safely.
* Budgets remain per runtime/process, as before; this is not a cross-shard global
  accounting service.
* The focused regressions do not exercise live multi-process IPC or BSD execution.

## Links

* [Security audit FED-10](../security-audit-report-2026-09-29.md#fed-10-resolving-sender-keys-for-relayed-pdus-bypasses-the-key-resolution-admission-budget)
* [HTTP transport](../http-transport.md)
* [Runtime architecture](../architecture.md)
