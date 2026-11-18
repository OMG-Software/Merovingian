# The RTC transport is advertised as type livekit with livekit_service_url

* Status: accepted
* Date: 2026-11-16

## Context and Problem Statement

MatrixRTC (MSC4143, with the LiveKit transport of MSC4195) is not in the Matrix v1.19 specification. Clients learn where
to get a LiveKit token from the homeserver, in three places: `GET /_matrix/client/v1/rtc/transports`, the older
`GET /_matrix/client/unstable/org.matrix.msc4143/rtc/transports`, and the `org.matrix.msc4143.rtc_foci` member of
`/.well-known/matrix/client`. This server has no token service of its own; the operator runs Element's
`lk-jwt-service` beside a LiveKit SFU. What does the server advertise, and how?

## Decision Outcome

Chosen option: "advertise the operator's service as type `livekit`", because released Element Web, Element X and
Element Call understand only that type.

* `server.rtc.livekit.service_url` (an HTTPS URL, refused when not one; never fetched by this server) is advertised as
  `{"type":"livekit","livekit_service_url":"<url>"}`. The entry has no `url` member. Clients build
  `<service_url>/sfu/get` and `<service_url>/get_token` by appending to it, so a URL with a query, or whose path ends
  in `/`, would give a broken request and is refused; a URL with no path (`https://host`, `https://host:8443`) is
  accepted, as are an IPv6 literal host and a port.
* Both routes need an access token and are rate limited like any client route. The stable path answers
  `{"transports":[...]}` and, with nothing configured, `{"transports":[]}`. The unstable path answers
  `{"rtc_transports":[...]}` and, with nothing configured, `{}`. Both mirror the reference server. The transport
  entry is identical on both, since one call can mix clients.
* `/versions` always carries `org.matrix.msc4143` and `org.matrix.msc4143.stable` as `true`: the routes exist
  whether or not a service is configured. Released clients call the unstable path only when the first is present;
  newer clients call the stable path when the second is.
* `/.well-known/matrix/client` carries `org.matrix.msc4143.rtc_foci` (the same entry in a list) only when a service
  URL is configured, and is otherwise byte for byte what it was. Clients built on the Rust SDK fall back to it.

A future reader must not "fix" the type to the MSC's stable name `m.livekit` without also adding the token
endpoints.

## Pros and Cons of the Options

### Type `m.livekit`

* Bad, because released clients do not parse it.
* Bad, because it tells a client to fetch tokens from the homeserver, a `/rtc/livekit/*` endpoint that does not exist.

### A different type on each path

* Bad, because a call can mix clients that use different paths.

### Drop the well-known member because MSC4143 rejected well-known discovery

* Bad, because Rust SDK based clients still fall back to it.

## Links

* Related: [ADR-0821](0821-server-turn-uris-is-added-beside-server-turn-server-which-is-kept.md)
