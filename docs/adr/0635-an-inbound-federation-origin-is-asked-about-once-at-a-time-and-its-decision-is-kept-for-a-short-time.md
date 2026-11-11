# An inbound federation origin is asked about once at a time, and its decision is kept for a short time

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.policy-server-budget.four-concurrent-calls-per-surface-decide-all-inbound-federation`

## Context and Problem Statement

With a policy server configured, every verified inbound federation request cost one synchronous call, admitted through
`policy_server_budget` (ADR-0361): 4 in flight for the federation surface at the default 32 request threads. A request
that found the budget full was "no usable decision", which `policy_server_allow_without_result` turned into a refusal for
everyone (false) or an allowance for everyone, a blocked origin included (true). A peer that kept more than four calls
in flight chose the outcome for every other peer, and the per-origin rate limits do not apply before the ask. Can an
origin's outcome be made independent of other origins' load?

## Decision Drivers

* The question sent is the surface, the entity and this server's name. For the federation surface the entity is the
  origin, so the answer is a function of the origin. For registration, rooms and media the entity is a user, a room or a
  media ID that does not repeat, and a remembered answer would be wrong or useless.
* The fail-open or fail-closed behaviour of each surface must stay as it is.
* The budget exists so a slow policy server cannot hold the request threads (ADR-0361).

## Considered Options

* Remember a real decision per origin for 30 seconds; let one request at a time ask for an origin and the others wait for
  it; use a remembered decision up to ten minutes old only when the budget has no place left
* Wait for a place in the budget instead of failing at once
* Cache every surface
* Give each origin a quota of places

## Decision Outcome

Chosen option: "a short per-origin decision cache with one asker per origin" (`trust_safety::PolicyDecisionCache`,
`HomeserverRuntime::policy_decision_cache`).

* Only a decision the policy server really gave (`decision_received`) is kept. An unreachable server, a refusal, an
  unparseable answer and a missing place are never kept, so `policy_server_allow_without_result` decides them as before.
* An origin costs at most one place in the budget however many of its requests arrive together; the others wait, with
  `runtime.mutex` released, for the asker's answer for up to `policy_server_timeout`, and have no decision if it has none.
* A fresh decision (under 30 s) is used without asking, so the ask rate follows the number of origins and not the number
  of requests. The cache holds 1024 origins and forgets the oldest; an origin being asked about is never forgotten.
* When the budget has no place, the origin's last decision is used if it is under ten minutes old. That is the only
  failure it covers, so an origin the policy server has denied stays denied while others hold the budget, in fail-open
  mode too.
* The seam `trust_safety_policy_server` goes through the same cache.

Waiting for a place was rejected: a waiting request holds its request thread as surely as one making the call, so the
bound ADR-0361 set would have to count waiters (ADR-0310) and refuse the same requests a moment later. A quota of places
for each origin was rejected: an attacker with a signing key per server name has as many origins as it likes.

### Negative Consequences

* A policy change for an origin takes up to 30 seconds to apply to requests the cache answers. The operator's local
  rule (`find_policy_rule`) is read first, on every request, and is not delayed.
* Residual: an origin never decided about, asking while enough other cold origins hold the whole federation budget,
  is still judged by `policy_server_allow_without_result`. That takes as many valid server names as there are places.

## Links

* Refines [ADR-0361](0361-the-policy-server-is-an-operator-trusted-destination-resolved-in-the-hook-and-admitted-through-a-budget.md)
