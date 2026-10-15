# Bind worker EDU relays to live main-verified requests

* Status: accepted
* Date: 2026-10-14

## Context and Problem Statement

FED-12 identifies a worker-to-main trust gap: authenticated encrypted IPC proves
which worker sent a frame, not which federation origin main authenticated.
EDUs lack the per-event signatures main re-verifies for relayed PDUs. A worker's
claimed origin must therefore be checked against main-owned request metadata.
Channel-local numeric IDs can collide between shards and worker generations.

## Decision Drivers

* Preserve Matrix v1.19 request authentication and existing EDU sink checks.
* Reject missing, mismatched, completed, expired and stopped request contexts.
* Keep reader routing and failure cleanup independent of runtime/sink locks.
* Preserve persisted data, cryptographic derivation and unrelated shared repairs.

## Considered Options

* Trust the worker's origin, or look it up on the supervisor's latest channel.
* Retain a global origin map independent of the pending-request lifecycle.
* Bind owned verified identity to the exact channel's pending request and check
  admission after acquiring the runtime lock.
* Hold the pending-map mutex across the complete EDU sink operation.

## Decision Outcome

Choose channel-local pending metadata. Main copies its signature-verified origin
into the pending entry before sending the federation request. An ordinary request
with no main-owned verified origin cannot authorize an EDU. The worker includes
the original federation frame's numeric `parent_request_id` in each EDU relay.
A thread-local RAII scope propagates that ID through each synchronous worker task;
it neither shares one mutable parent across threads nor rewires a shared sink.

The supervisor supplies the exact receiving channel through a callback installed
on that channel before start. The callback weakly references its own channel to
avoid an ownership cycle; queued handler-pool work retains a strong reference.
No later supervisor snapshot selects a relay's security context.

Under the runtime lock, immediately before the real sink, main checks that the
receiving channel is running and healthy, the parent is present and not ready,
the monotonic deadline has not expired, and the claimed origin exactly matches
the owned verified origin. Missing and mistyped IDs cannot select a valid parent.
The pending mutex protects only this check and never covers a runtime-lock wait
or sink callback. Admission linearizes at that check: work already admitted may
finish after parent completion or shutdown. This is not cancellation/rollback
of an already admitted database operation.

The deadline is computed with checked conversion/addition before pending
publication and includes time waiting to write. The deadline does not interrupt
a kernel-blocked socket write; it bounds relay authorization and reply waiting,
not an otherwise unbounded blocking write operation.

### Positive Consequences

* Main no longer treats worker JSON or a guessed ID alone as authenticated identity.
* Completed replies, deadlines and channel failure revoke future admission.
* Existing receipt ACL/member checks and to-device sender/locality/dedup remain.
* No persisted schema, signing-key derivation, stored session or digest changes.

### Negative Consequences

* Main and worker must be deployed/restarted together. An older worker omitting
  the parent field fails closed against the new main; no unchecked legacy EDU
  handler overload is retained.
* An ID is a routing reference, not a secret capability. A compromised worker can
  choose another active request for the same origin. Origin correlation does not
  prove the EDU content was in that request's signed body; signed-content binding
  remains outside this repair.
* Holding the pending mutex across the sink would block reply/failure progress;
  a global origin map or current supervisor snapshot would lose channel/lifecycle
  identity. Those alternatives are rejected.

## Verification and Acceptance

Proposed, not accepted. The real-signature/encrypted-IPC/SQLite regression has an
inspected behavioral RED: normal build succeeded, 109 assertions executed,
97 passed and 12 failed at mismatch, poisoned retry and completed-parent checks.
Healthy A delivery and both real signature controls passed. Earlier fixture
registration/discovery failures are not behavioral RED and are retained separately.

The repair, worker propagation and legitimate-fixture migration are implemented.
Normal post-format runs pass the origin regression (109 assertions / 1 case),
related worker EDUs (173 / 5), worker integration (2059 / 38), actual socket-HTTP
and separate-worker mixed PDU/EDU control (262 / 1), and federation proxy (12 / 2).
Unit runs pass lifecycle checks (49 / 2), IPC (396 / 50), worker (340 / 42) and
sync handlers (382 / 16). The lifecycle scenarios are supplemental first-GREEN
coverage, not an additional tests-first RED. All 79 focused bindings are stable
and current. The 11-file added-lines scan, including the complete new helper,
has no pattern indicators; all 11 owned range-format checks pass.

Independent source review and a fresh combined checkpoint remain pending.
Mirrored encrypted-pair dispatch alone does not establish production wiring;
the separate-worker control verifies legitimate production propagation, not an
adversarial worker-generation restart race. No whole-finding or release closure
is claimed.

## Links

* [Matrix v1.19 request authentication](../matrix-v1.19-spec/server-server-api.md#request-authentication)
* [Security audit, FED-12](../security-audit-report-2026-09-29.md)
* [Architecture](../architecture.md#federation-worker-consistency-model)
