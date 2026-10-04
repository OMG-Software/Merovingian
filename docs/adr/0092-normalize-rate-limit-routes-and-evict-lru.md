# Normalize known rate-limit routes and evict least-recently-used buckets

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Rate-limit keys include request paths, and several Matrix routes place
client-controlled identifiers in those paths. Keeping those values in the key
lets one logical endpoint create a bucket per room, event, transaction, or
media ID. Unknown paths also need one shared fallback bucket, while known route
actions and existing operator prefix policies must remain independently
meaningful. In addition, evicting by scanning the bounded table would make each
new attacker-chosen key cost O(n) at capacity.

## Considered Options

* Normalize only recognized route templates and share one fallback for unknown paths; resolve policies against both normalized and original path.
* Use one broad route-prefix bucket for every path beneath a client-server prefix.
* Keep path values in keys and rely on the table capacity to bound growth.
* Scan for a stale or least-recently-used entry when a table reaches capacity.

## Decision Outcome

Normalize only paths that match known route shapes, replacing their variable
components with fixed placeholders while retaining the action name. Map every
unmatched path to one shared fallback bucket. Resolve operator prefix policies
against both this normalized route and the original query-free target, so
existing prefixes keep applying and operators can configure route templates.

Bound each per-IP and per-user bucket table with a recency list. Touching an
existing bucket moves it to the list tail; admitting a new key at capacity
evicts the list head and matching map entry. This avoids a table scan on the
request path. Keep the engine non-copyable and non-movable because its bucket
entries hold iterators into the engine-owned recency lists. Checks remain under
the existing runtime lock; this decision does not introduce concurrent engine
access.

### Positive Consequences

* Variable identifiers cannot mint a separate bucket for each request on the
  covered routes.
* Unknown paths share one fallback bucket without merging recognized actions.
* Existing operator prefixes remain effective; normalized templates may also
  be used for route-wide overrides.
* A new key at capacity incurs one expected-O(1) eviction rather than a table
  scan.

### Negative Consequences

* The known-route matcher must be updated when new dynamic endpoints are added;
  unrecognized routes intentionally use the shared fallback.
* LRU eviction permits an attacker with enough distinct keys to displace old
  counters, though table memory and per-admission eviction work stay bounded.

## Links

* [HTTP-3 audit finding](../security-audit-report-2026-09-29.md#http-3--rate-limit-buckets-are-keyed-on-the-raw-path-so-varying-a-path-segment-bypasses-them)
* [HTTP transport rate-limit policy](../http-transport.md#rate-limit-policy)
