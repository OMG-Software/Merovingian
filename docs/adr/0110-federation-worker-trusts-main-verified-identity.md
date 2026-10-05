# Federation worker trusts the main-process verified identity for room-scoped reads

* Status: accepted
* Date: 2026-10-05

Technical Story: security audit follow-up to DB-2 / ADR-0108. The federation worker receives inbound room-scoped requests from the main process over an authenticated IPC channel after main has verified the X-Matrix signature. Requiring the worker to resolve and rediscover the remote peer independently blocked tests that have no production DNS/key-fetch seam, and duplicated policy enforcement that main had already performed.

## Context and Problem Statement

Main and the out-of-process federation worker split inbound federation handling: main verifies the X-Matrix Authorization header and forwards only the verified origin/key_id to the worker. The worker then calls the same `resolve_inbound_remote` path used by main, which expects a full remote record from the injected remote-key resolver. In production the worker has its own network resolver, but in tests the resolver is a main-process test seam and the worker has no equivalent hook. Room-scoped read endpoints (`/state`, `/state_ids`, `/event`, backfill, etc.) do not need the remote's signing key; they only need the verified origin for server-ACL checks. Re-resolving the remote in the worker therefore adds no security value while making the fallback path introduced by ADR-0108 unreachable in the test harness.

## Decision Drivers

* Main is the authoritative policy enforcement point for inbound federation.
* A request that reaches the worker has already passed X-Matrix verification, server policy, discovery policy, and trust policy in main.
* Room-scoped read endpoints must remain testable without giving the worker a production network path.
* The mechanism must not weaken the fail-closed property for requests that arrive directly at the worker without main verification.

## Considered Options

1. **Give the worker its own test-only remote-key resolver hook.** Matches the main-process seam but exposes a new test API in the worker process and duplicates the resolver state across processes.
2. **Forward the full remote record inside the IPC `fed_request` frame.** Carries discovery, trust, and signing-key state across the channel, but adds serialization complexity and makes the worker depend on main's trust snapshot staying fresh.
3. **Trust the verified identity already carried by the IPC frame and synthesize a minimal remote record in the worker.** Keeps main as the sole policy enforcement point, adds no new IPC fields, and still requires `signature_verified` to be true before bypassing resolution.

## Decision Outcome

Chosen option: "Trust the verified identity already carried by the IPC frame and synthesize a minimal remote record in the worker".

Implementation:

* `resolve_inbound_remote` in `src/federation/inbound_request.cpp` checks `request.signature_verified` after route matching.
* When `signature_verified` is true, the function skips server policy, remote-key resolution, discovery policy, and trust policy, and returns a synthetic `FederationRemoteRuntime` containing only the verified origin and key ID.
* When `signature_verified` is false, the existing full resolution and policy sequence remains unchanged, so direct inbound requests to either process still fail closed.

### Positive Consequences

* The worker can serve room-scoped reads without a redundant network resolution step.
* Tests can exercise worker snapshot fallback without simulating full DNS/key discovery in the worker process.
* The security boundary is preserved: only main-verified identities bypass the worker-side resolver.

### Negative Consequences

* The worker does not independently re-evaluate discovery/trust policy for main-forwarded requests; it relies on main having done so.
* Endpoints that need the remote's public signing key (e.g., authorizing PDUs inside `/send`) still require a real remote record and therefore keep the existing resolution path.

## Pros and Cons of the Options

### Give the worker its own resolver hook

* Good, because it preserves the worker's independent policy checks.
* Bad, because it adds a second resolver interface and state to maintain.
* Bad, because it does not solve the problem for tests that set the resolver only in main.

### Forward the full remote record in IPC

* Good, because the worker would have the same record main used.
* Bad, because it widens the IPC message and couples the worker to main's trust state.
* Bad, because trust state can change between the forward and the worker's dispatch.

### Trust the verified identity and synthesize a minimal record

* Good, because it is the smallest change that unblocks the worker fallback tests.
* Good, because it keeps main as the single policy enforcement point.
* Bad, because the worker cannot enforce additional policy for these specific requests without main's involvement.

## Links

* Related to [ADR-0108 - Federation worker stale snapshot fallback to main](0108-federation-worker-stale-snapshot-fallback-to-main.md)
* Related to [ADR-0078 - The federation worker never signs](0078-the-federation-worker-never-signs.md)
