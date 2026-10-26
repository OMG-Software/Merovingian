# Federation may reach operator-named private networks, and nothing else

* Status: accepted
* Date: 2026-10-26

## Context and Problem Statement

Outbound federation refuses every private, loopback, link-local, CGNAT,
multicast and reserved address, with no override (`federation/security.cpp`).
That is the right default on the public internet. It also makes the server
impossible to test with Complement, the external Matrix test suite that the
1.0.0 milestone requires: Complement's homeservers and its in-process fake
federation servers sit on Docker bridge networks (`172.16.0.0/12`, or
`192.168.65.0/24` on Docker Desktop), reached as `hs2` or
`host.docker.internal:<port>`. A private federation on a LAN or VPN has the
same problem.

How can federation reach those peers without weakening the SSRF boundary for
anything else?

## Decision Drivers

* Complement must test the binary that ships, not a build made for it.
* No setting may open loopback, link-local (cloud metadata), CGNAT, multicast
  or reserved space.
* URL preview, media redirects, push gateways and identity servers fetch
  URLs that clients or users choose. The exception must never reach them.
* The opening must be loud: visible in config review and in the logs on every
  start.

## Considered Options

* A runtime setting, `security.federation.allow_private_ip_ranges`, holding
  explicit CIDRs confined to RFC 1918 and ULA space.
* A compile-time Meson option that disables the block in a Complement build.
* Reusing `TestOnlyForcedOutboundResolution`, the per-destination test seam in
  `runtime.hpp`.

## Decision Outcome

Chosen option: the runtime setting, because it is the only one under which
Complement exercises the release artifact.

* An entry must be a CIDR with an explicit prefix and no host bits, wholly
  inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7`
  (`config::private_ip_range_is_allowable`). Anything else is a startup error.
* The matcher (`federation::ip_address_in_allowed_private_range`) re-checks
  every range with the same function and ignores one that fails. A list that
  bypassed config validation still cannot open loopback or link-local space.
* An allowed address passes both the built-in block and
  `security.federation.deny_ip_ranges`. The default deny list covers all of
  the private blocks, so a narrower allowance has to win for the setting to
  mean anything. Allowed ranges can only ever be private, so this never opens
  public space the operator denied.
* It applies to federation only: `discover_server` and its branches,
  well-known fetches, the cached discovery's `discover`, the inbound origin
  check (`federation_discovery_policy`) and the re-check of remote media
  addresses. `resolve_federation_destination` uses it only when the caller
  passes it, so URL preview and media redirects, which share the discovery
  network, never get it. `CachedServerDiscovery::lookup_addresses_filtered`,
  used by pusher gateways and identity servers, does not apply it.
* Each allowed range is logged at CRITICAL on every start.
* Changing it requires a restart, like every `security.federation.*` key.

### Positive Consequences

* Complement and other Docker or LAN harnesses can run against the shipped
  server with configuration alone.
* Operators of a private federation get a supported, narrow switch instead of
  patching the source.

### Negative Consequences

* A misconfigured production server can reach internal hosts in the named
  ranges over federation. The CRITICAL log line and the narrowness of the
  ranges are the mitigations.
* A new outbound caller that shares the discovery network must decide
  explicitly whether the allowance applies. The default is no.

## Pros and Cons of the Options

### A compile-time option

* Good, because a release build cannot contain the opening at all.
* Bad, because Complement would test a different binary from the one that
  ships, which defeats the purpose of external release evidence.

### Reusing `TestOnlyForcedOutboundResolution`

* Good, because no production code path changes.
* Bad, because it is keyed by destination, and Complement's fake servers
  listen on random ports chosen per test.
* Bad, because it is only reachable from test code, not from a running server.

## Links

* [ADR-0049](0049-treat-the-specification-as-the-conformance-authority.md)
* `docs/todos/production-milestone.md`, "What blocks 1.0.0"
