# A server that gave no answer to a profile lookup is not asked again for a minute

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

Technical Story: production log of pong.ping.me.uk at 1.0.2, 2026-11-15: eight `profile.proxy` timeouts to
example.org in two minutes.

## Context and Problem Statement

`GET /_matrix/client/v3/profile/{userId}` for a user of another server asks that server's `query/profile`. The call
holds a client outbound slot (ADR-0079, ADR-0751) and runs under the directory deadline. Clients make these lookups
by themselves, for member lists, hover cards and invite dialogs, and retry them. In the log, a client looked up a
user on example.org, which runs no Matrix server: discovery fell back to port 8448, every connection timed out, and
each of eight lookups in two minutes waited out the deadline and logged a warning.

The server discovery cache does not help: discovery succeeded, and only the connection failed. Should a server that
has just given no answer be asked again on the next lookup?

## Decision Drivers

* A lookup is interactive and cheap to repeat. A short delay before a recovered server is asked again costs a
  client one missing display name, while a dead server costs a slot and the full deadline per lookup.
* Only the destination's silence should count. An HTTP answer of any status proves the server is there, and a
  refusal made locally (federation policy, deadline, missing key) says nothing about it.
* The record must stay bounded, since a client chooses which servers are looked up.
* ADR-0262 and ADR-0749 keep joins and outbound delivery from serving remembered failures. Those retries are paced
  by their own backoff or by the user; a profile lookup has neither.

## Considered Options

* Remember each server that gave no answer to a profile lookup for 60 seconds, in a bounded record guarded by
  `runtime.mutex`, and answer lookups for it 502 at once during that time.
* Serve remembered discovery failures to profile lookups, as key resolution does.
* Shorten the directory deadline for profile lookups.

## Decision Outcome

Chosen option: the first. `perform_outbound_call` sets `OutboundCallResult::remote_unreachable` when discovery
found no server or the request got no connection, no verified TLS session or no response in time
(`unresolved_host`, `connection_failed`, `tls_verification_failed`, `timeout`, `network_error`). A redirect, an
oversized body and an error status are answers. `remote_profile_response` records such a server in
`HomeserverRuntime::profile_unreachable_servers` (`RecentlyUnreachableServers`: 60 s, at most 4096 servers, expired
entries and then the oldest dropped when full). While it is recorded, a lookup for any of its users is answered 502
`M_UNKNOWN` with no outbound call, logged at DEBUG. A server that answers at all is forgotten: `perform_outbound_call`
sets `OutboundCallResult::remote_answered` for any HTTP response, a redirect it refuses to follow and an oversized
body included. `remote_status` is 0 for those two, so it is not the test; a lookup overlapping one that failed would
otherwise leave the server recorded although it had just answered.

The record covers profile lookups only. Other client-triggered calls (public room directory, thirdparty) are made
when a user asks for them, not automatically, so they keep asking every time.

### Positive Consequences

* A dead server costs one slot and one deadline per minute of lookups, not one per lookup, and logs one warning a
  minute.
* Slots stay free for lookups to servers that do answer.

### Negative Consequences

* A server that comes back is not asked for up to 60 seconds after its last failure.
* The record is in memory, per process, and is lost on restart.

## Pros and Cons of the Options

### Serve remembered discovery failures

* Good, because the cache already exists.
* Bad, because the observed case failed after discovery succeeded, so it would not have been covered.

### A shorter deadline for profile lookups

* Good, because it needs no state.
* Bad, because a slow but working server would then fail every lookup, and a dead one still costs a slot per lookup.

## Links

* Bounded by [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) and
  [ADR-0751](0751-the-per-client-outbound-call-cap-is-configurable-and-defaults-to-three.md)
* Contrasts with [ADR-0262](0262-a-join-reuses-server-discovery-but-never-a-remembered-failure.md) and
  [ADR-0749](0749-outbound-delivery-never-serves-a-remembered-discovery-failure.md)
