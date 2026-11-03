# The policy server is an operator-trusted destination, resolved in the hook and admitted through a budget

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-42 (`trust-safety.policy-server-hook-no-pinned-addresses-always-unreachable`).
Owner decision, 2026-11-03: the policy server is operator-trusted.

## Context and Problem Statement

`resolve_policy_server_hook` built an `http::OutboundRequest` and called `OutboundClient::perform` without setting
`pinned_addresses`. `perform` resolves nothing and answers `unresolved_host` for an empty pin list, so with the real
transport the hook was always "unreachable": a deployment with `policy_server_allow_without_result=false` refused
every guarded workflow (registration, createRoom and upgrade, media downloads, inbound federation), and one with
`true` never asked the server. Fixing it makes each guarded request a real network round trip on a request thread,
some of them before authentication. How is the host resolved, in which process does the hook run, and what bounds the
threads it holds?

## Decision Outcome

* **Operator-trusted resolution.** `policy_server_url` is configured by the operator, not chosen by a peer or a client,
  so the hook resolves its host with `discovery_network->lookup_addresses` (no SSRF deny-list), as the appservice client
  does for its registration URL. A policy server on a private network works. The host and port come from
  `http::parse_outbound_url`; certificate validation is unchanged (HTTPS only, system trust, or the test CA seam).
* **Inside the lock-release scope, bounded.** Everything read from the runtime (config, resolver, client) is read first;
  the resolution and the call both run in the `RuntimeLockRelease` scope. The call is given what is left of
  `policy_server_timeout` after the lookup, and a lookup that spent all of it is a failure. `getaddrinfo` itself takes as
  long as the system resolver is configured to; the budget below bounds how many threads can be in it.
* **Main decides.** The hook runs in main for every surface. Federation requests are judged once, before the proxy
  forwards them (ADR-0358), so the worker is not asked to resolve or connect for it and its seccomp and
  Landlock profile need no widening. The resolution code does not depend on the process.
* **Admission.** Each call takes a place in `HomeserverRuntime::policy_server_budget` first: at most a quarter of the
  main pool (min 2) across all surfaces, and half of that for any one surface (key: the surface name), so a flood of
  verified federation requests leaves registration and room creation a place. No place means "no usable decision":
  the same as an unreachable server, so `policy_server_allow_without_result` decides it: `false` (the default) refuses the
  workflow, `true` allows it. The fail behaviour is unchanged and now also covers over-capacity.
* **Visible failure.** A transport error is logged at warning level with its `OutboundError` name and detail.
* **Test seams.** `HomeserverRuntime::test_policy_server_trusted_ca_pem` (empty in production) and a replaceable
  `discovery_network`.

### Negative Consequences

* A refused call under load looks like an unreachable server to the policy engine; an operator tuning `request_threads`
  should read the warning, not only the audit.
* An operator who points `policy_server_url` at an address that reaches an internal service gets what they configured.

## Links

* Related to [ADR-0358](0358-main-applies-the-admin-federation-policy-to-every-verified-request.md) and
  [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) (the same shape of cap)
* Related to [ADR-0362](0362-reserve-a-pre-v12-room-id-across-the-policy-hook.md)
