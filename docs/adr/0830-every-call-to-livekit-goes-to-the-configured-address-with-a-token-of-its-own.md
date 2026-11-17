# Every call to LiveKit goes to the configured address with a token of its own

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

The built-in token service (ADR-0829) calls LiveKit's room service. Each call is signed with the API secret, so a call
to the wrong address would hand that address a token valid on the SFU. A call is also an outbound request made on a
client's behalf, with what that costs the request pool. This record lists every call and the rules each follows; a new
call is added here.

## Decision Outcome

### Where a call goes

* A call goes only to `server.rtc.livekit.api_url`, never to an address a request names.
* `livekit_create_room_request` parses the URL again with `http::parse_outbound_url` and holds it to the
  configuration's rule (`https`, or `http` to a loopback IP literal). It rebuilds the URL from the parsed parts with an
  explicit port and appends `/twirp/livekit.RoomService/<Method>`.
* `perform_livekit_request` resolves the host with `discovery.upstream().lookup_addresses`, the operator-trusted lookup
  the application service client uses (ADR-0515). The connection is pinned to the addresses found.
  * The SSRF-filtered lookup is not used: the operator chose the address, and LiveKit commonly runs on the same host or
    LAN.
* TLS verification is always on and redirects are refused (`http::OutboundClient`).

### How a call is made

* Every call is made from a client request with an ADR-0079 slot held, under one deadline, and with `runtime.mutex`
  released around the call only (`src/homeserver/AGENTS.md`).
* At most 16 KiB of answer is read (`livekit_response_max_bytes`). Nothing in an answer is trusted or returned to the
  client: only the HTTP status is read.

### What each call may do

* Each call carries its own Twirp bearer token. The token is signed by a typed function in `crypto/LiveKitToken`
  (ADR-0828), is valid for 60 seconds, and grants only what that call needs.

| Call | Method | Grant | When |
|---|---|---|---|
| Create the room | `POST /twirp/livekit.RoomService/CreateRoom`, body `{"name", "empty_timeout": 300, "departure_timeout": 20}` | `video.roomCreate` only | Before a publishing token is issued (MSC4195 MUST) |

No call removes a participant, ends a room, changes permissions or reads metadata. Adding one is a change to this
record and a new typed signer, and a call that acts against a participant (for example `RemoveParticipant`) needs the
owner's decision first.

### Tests

* `HomeserverRuntime::test_livekit_perform` stands in for LiveKit. It is handed the finished request, token included,
  and returns LiveKit's answer, so tests check the address, the method, the grant and the body without a network.

### Positive Consequences

* A leaked call token can create a room for one minute and nothing else.

### Negative Consequences

* Each publishing token costs one round trip to LiveKit while a request thread waits. The slot and the deadline bound
  it.

## Links

* Refines [ADR-0829](0829-the-built-in-livekit-token-service-issues-tokens-only-to-users-this-server-finds-joined.md)
* [ADR-0079](0079-cap-client-triggered-outbound-proxying.md)
