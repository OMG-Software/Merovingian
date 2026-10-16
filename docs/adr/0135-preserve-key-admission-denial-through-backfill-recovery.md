# Keep backfill key admission and local-denial provenance inside recovery

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

Missing-reference recovery verifies fetched events before storing outliers or
promoting snapshot state. Its direct signing-key resolver invocation bypassed
FED-10's shared quota, in-flight cap and bounded pair failure cache. Existing
backfill HTTP call/deadline limits do not admit discovery-bearing signing-key
resolution. Main relay fixes did not cover this separate caller.

Recovery returned only whether it stored anything. Treating a local key-admission
refusal as a normal missing-reference gap would return the existing missing-state
result and could accept/deduplicate the enclosing transaction instead of preserving
its transient overload and unchanged-transaction retry.

## Considered Options

* Retain direct resolver calls under the existing backfill request limits.
* Admit verification keys, but collapse local refusal into unresolved state.
* Reuse the admitted key-only helper and carry local refusal through recovery.

## Decision Outcome

Chosen option: "Reuse the admitted key-only helper and carry local refusal through
recovery", because neither separate HTTP limits nor an unresolved-state result
preserves the key-network boundary and retry semantics.

Every fetched-event verification, including snapshot and auth-chain recovery,
uses `resolve_verification_key`. Exact matching cache material requires no full
resolver or outbound permit; signature, content-hash, event-time key validity
and auth/state checks remain in their original order.

Recovery shares main's unknown-source bucket. These recovery inputs provide no
main-validated client address; the sending peer or worker-supplied origin is not
a trustworthy source-address quota selector. This trades per-client fairness for
a bounded common cold-key path without an IPC metadata migration.

A request-local backfill budget records structured local key denial. It stops
subsequent recovery calls and carries that denial in an explicit recovery result.
The enclosing PDU returns the existing `main_overloaded` result rather than a
normal missing-state result. Existing transaction handling then returns 503,
defers EDUs and leaves the original transaction retryable. Local denial does not
create a key-failure cache entry or charge a remote trust failure.

### Positive Consequences

* Backfill, snapshot and auth-chain key lookup use the same admission/cache seam
  as main relay verification, without persisted or IPC format changes.
* Cache-only verification works under exhausted quota or occupied foreign slots.
* Local denial cannot silently accept the enclosing missing-state transaction.
* Real loopback TLS/SQLite regression observed 13 behavioral failures before the
  repair, then verified denial without blocked-event persistence and unchanged
  PDU retry after admission recovers.

### Negative Consequences

* Cold-key recovery across unrelated clients shares one conservative bucket.
* Already verified outliers from earlier recovery steps are not rolled back;
  successful retry still relies on event-ID idempotency.
* Limits are per runtime/process, not aggregate across all shards. Whole-finding
  acceptance still requires independent review and end-to-end worker HTTP
  overload propagation coverage; this decision does not claim either.

## Links

* Refines [ADR-0134](0134-share-key-admission-with-main-worker-relay-verification.md).
* Preserves [ADR-0133](0133-preserve-local-key-admission-denial-separately-from-remote-failure.md).
* Preserves [ADR-0132](0132-separate-cached-verification-keys-from-budgeted-discovery.md).
