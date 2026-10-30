# This server neither serves nor consults notary key servers

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement run 12, `TestUnknownEndpoints/Key_endpoints`

## Context and Problem Statement

The Server-Server API v1.19 ("Querying Keys Through Another Server") lets a server ask a notary for
another server's signing keys: "Servers may query another server's keys through a notary server. The
notary server may be another homeserver." A notary serves `GET /_matrix/key/v2/query/{serverName}`
and `POST /_matrix/key/v2/query`, fetches the keys from each queried server's `/_matrix/key/v2/server`,
signs the result with its own key and may answer from a cache when the queried server is offline.
The spec marks both endpoints as needing no authentication and as not rate-limited.

This server has never implemented either side. It fetches each server's keys from that server's own
`/_matrix/key/v2/server` and serves only its own keys there. Nothing recorded that this was a choice,
so Complement's `TestUnknownEndpoints/Key_endpoints` (a `PUT` to `/_matrix/key/v2/query` expecting
405) read as a missing feature. Should the notary endpoints be built?

## Decision Drivers

* Serving a notary helps only other servers whose administrators choose this server as a trusted key
  server; no Matrix flow requires any server to be one.
* The endpoints are unauthenticated and, per the spec, not rate-limited: every request makes this
  server fetch from servers the caller names. That is an outbound amplification and request-forgery
  surface on the listener most exposed to hostile traffic.
* A notary signs other servers' key responses with this server's key, so a mistake in the fetch or
  the cache puts this server's signature behind a key it should not vouch for.
* Consulting notaries would only help verify events from servers that can no longer serve their own
  keys, and it trusts the notary's view of a third server.

## Considered Options

* Neither serve nor consult notaries
* Serve the notary endpoints behind the outbound admission caps (ADR-0079) and the private-range rules
* Consult notaries (e.g. a configured trusted key server) when a server cannot serve its own keys

## Decision Outcome

Chosen option: "Neither serve nor consult notaries", because the feature is optional in v1.19, helps
only third parties who opt in, and costs an unauthenticated outbound-fetch surface plus signing
exposure on this server's key.

### Positive Consequences

* No client of the federation listener can make this server fetch from a host it names.
* This server's signing key signs only its own keys and its own events.

### Negative Consequences

* `/_matrix/key/v2/query` is an unknown endpoint here, so any method on it is answered 404
  `M_UNRECOGNIZED` (spec, "Unsupported endpoints"). Complement's `TestUnknownEndpoints/Key_endpoints`
  expects 405 and is listed as an expect-fail `spec` entry.
* Events signed by a server that can no longer serve its own keys cannot be verified through a
  notary; they are treated like any event whose signing key cannot be resolved.

## Links

* Related to [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) (the caps a notary would need)
* Related to [ADR-0274](0274-method-not-allowed-is-decided-by-a-static-table-and-by-fall-through.md)
