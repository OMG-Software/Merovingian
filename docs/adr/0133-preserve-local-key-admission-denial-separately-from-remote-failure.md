# Preserve local key-admission denial separately from remote failure

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

The FED-10 admission wrapper initially returned the same missing-key result for
local quota/capacity rejection and actual failed sender resolution. Transaction
handling therefore penalized an authenticated relay for local overload, could
activate peer backoff after three valid relayed PDUs, and recorded the transaction
as accepted, preventing its original ID from being retried.

Restricted-join secondary-signature lookup and direct membership/invite paths
must preserve the same distinction. The public authorization resolver still
returns an optional peer record, so its adapter cannot erase failure provenance.

## Decision Drivers

* Local resource exhaustion is not evidence of remote misbehavior.
* Genuine remote failures and invalid signatures must retain their penalties,
  including when mixed with locally deferred PDUs.
* Preserve cached verification, admission ownership and asynchronous lifetimes.
* Keep public resolver, persisted-key and IPC formats unchanged.

## Considered Options

* Treat every missing key as a remote failure and return normal per-PDU errors.
* Exempt all failed key lookups from trust accounting.
* Return immediately on the first local denial and omit remaining trust checks.
* Preserve explicit failure provenance through resolution and authorization.

## Decision Outcome

Choose explicit internal resolution outcomes carrying either a key or the failure
kind. Local quota/capacity or invalid-local-policy denial is distinct from an
actual failed resolution or its negative-cache hit. Cache identity checks and
signature/event-time validity checks remain unchanged.

Parallel pre-resolution tasks own disjoint result values. The public optional
resolver is adapted only around its synchronous authorization invocation, with
failure provenance scoped to that invocation; it is not a shared asynchronous
flag.

A transaction with any locally deferred PDU returns retryable 503, dispatches no
EDUs and is not inserted into accepted-transaction dedup. Local denial alone does
not change or reset relay trust. Continue evaluating the remaining PDUs so actual
failures in a mixed transaction retain their penalties. Direct membership/invite
requests similarly return 503 without reaching their acceptance hook.

### Positive Consequences

* A valid relay cannot enter peer backoff merely because another request owns
  the outbound capacity, and its original transaction remains retryable.
* Local overload cannot erase genuine failure accounting in mixed transactions.
* Cached verification remains usable while quota or capacity is exhausted.

### Negative Consequences

* Some otherwise valid PDUs may already have reached ingestion before the
  transaction returns 503. Retry relies on event-ID idempotency, as with the
  existing main-ingestion overload path; transactions are not atomic batches.
* The sending peer retries the original transaction until it receives 200, so
  local overload can delay its later transactions. Reporting 200 and silently
  losing the deferred PDUs is not an acceptable alternative.
* This decision concerns core inbound admission. Main IPC re-verification's raw
  resolver accounting remains a separate whole-finding acceptance check.

## Links

* [ADR-0132](0132-separate-cached-verification-keys-from-budgeted-discovery.md)
* [Server-Server API transactions](../matrix-v1.19-spec/server-server-api.md#transactions)
* [HTTP transport](../http-transport.md#federation-signing-key-resolution-admission)
