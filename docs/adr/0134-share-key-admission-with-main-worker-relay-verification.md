# Share key-resolution admission with main's worker-relay verification

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

Main independently verifies every PDU, membership event and invite relayed by a
federation worker (ADR-0071). Its direct call to the complete remote-key resolver
bypassed the federation runtime's source quota, in-flight slots and server/key
negative cache. A fresh persistent signing key does not make complete peer
discovery network-free (ADR-0132).

The relay frames do not carry a main-validated client address. Trusting an
address supplied by the worker would let the least-trusted process select new
buckets. The cryptographic verification must remain independent of the worker,
including during overload.

## Considered Options

* Continue using the raw resolver, relying on IPC and handler-pool limits.
* Charge a client address or shard identifier supplied in a worker frame.
* Reuse core key-only resolution and admission with a shared unknown-source
  bucket for main relay misses.
* Change the IPC protocol now to bind relays to main's pending HTTP request and
  validated client address.

## Decision Outcome

Chosen option: "Reuse core key-only resolution and admission with a shared
unknown-source bucket for main relay misses". The additive
`resolve_verification_key` entry point delegates to the existing core sender
helper. Matching cached verification material bypasses discovery and spends no
outbound reservation. A miss uses main's configured source quota, in-flight cap
and bounded server/key negative cache. The existing guard owns and releases only
its own slot, including when the resolver throws.

Main supplies an empty source; it never accepts a source override from the
worker. All main relay misses therefore share the existing `<unknown>` bucket,
across the main runtime's handlers and worker channels. This is stricter than
separate client-address quotas and can defer legitimate cold-key traffic across
otherwise unrelated clients. It is not an aggregate budget for every process.

The result separately identifies local denial. PDU relays return the existing
`main_overloaded` status; membership and invite relays return unaccepted 503
responses, before acceptance hooks or persistent mutations. No denial enters
the negative cache. Genuine resolution failure remains a verification refusal.
Main still checks the sender signature, event-time key validity and signed-event
identity, and rebuilds the envelope from verified JSON. A cache read also works
when the complete resolver is not wired.

No persisted format or IPC schema changes are required. Trusted request-context
binding is a separate decision, not a worker-provided hint or an assumption that
this boundary already implements FED-12.

### Positive Consequences

* IPC and handler-pool bounds no longer substitute for configured key budgets.
* The same admission and exception-safe ownership rules apply at both boundaries.
* Local exhaustion defers work rather than accepting it or treating it as a bad
  signature; an unchanged relay can succeed after admission recovers.
* Network-free cached verification remains useful under quota/capacity pressure.

### Negative Consequences

* Main's shared unknown-source quota can reduce fairness for cold-key traffic.
* Other raw-resolver callers, including backfilled-event verification, still
  require their own reachability/accounting review before whole-FED-10 closure.
* In-process encrypted IPC tests do not establish separate-process or BSD behavior.

## Links

* [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
* [ADR-0132](0132-separate-cached-verification-keys-from-budgeted-discovery.md)
* [ADR-0133](0133-preserve-local-key-admission-denial-separately-from-remote-failure.md)
