# A federated LiveKit token request is judged by main and answered subscribe-only

* Status: accepted
* Date: 2026-11-17

Technical Story: MatrixRTC slice 4. The owner chose "relay out, subscribe-only in".

## Context and Problem Statement

In MSC4195 a client asks its own server for a token for another server's SFU. Its server relays the request to that
server's `POST /_matrix/federation/v1/rtc/livekit/get_token`, adding `user_id`. The receiving server must refuse:

* when it is not joined to the room (403 `M_FORBIDDEN`);
* when `user_id` is not of the origin (403 `M_FORBIDDEN`);
* when the user is not joined (403 `M_FORBIDDEN`);
* when `url` is not its SFU (400 `M_INVALID_PARAM`).

The relaying server passes 403 `M_FORBIDDEN` and 400 `M_INVALID_PARAM` back to the client, and turns anything else
into 502 `M_UNKNOWN`.

On this server, inbound federation is parsed by the federation worker. The worker holds no secret and signs nothing
(ADR-0078). The LiveKit API secret is main's (ADR-0829).

## Decision Drivers

* The worker never sees the API secret and never signs a token.
* A token goes only to a user this server's own state shows joined, for an origin main verified. Nothing the worker
  says is believed.
* A request from another server does not make this server call anything.
* What this server relays out goes only to a server its state shows in the room, under the client-outbound bounds.

## Decision Outcome

### Inbound: `POST /_matrix/federation/{v1,unstable/io.element.msc4195}/rtc/livekit/get_token`

1. Main verifies the X-Matrix signature in `FederationProxy::handle` and gives the forwarded request one relay permit
   (ADR-0595). The permit is `WorkerRelayKind::livekit_token` over the request body.
2. The worker routes the request and relays it to main in a `livekit_token_ingest` frame carrying the body and the
   origin.
3. Main admits the frame only when the origin matches the pending request's verified origin
   (`IpcChannel::matches_pending_origin`) and the body's digest consumes the permit (`consume_pending_relay`). A worker
   cannot change the origin or the body, or replay a frame.
4. Main judges the request with `issue_federation_livekit_token`, holding `runtime.mutex`, by its own state:
   * this server is in the room (`room_state_is_current`: the create event is held and a local user is joined);
   * `user_id`'s server is the origin;
   * the user's current `m.room.member` state is `join`;
   * `url` is `server.rtc.livekit.url`, byte for byte.

   The first three are one 403 `M_FORBIDDEN`, "No token can be issued for this user in this room.", so a server learns
   nothing about a room it has no member in. The last is 400 `M_INVALID_PARAM`. A body naming a `server_name` other
   than this server's is 400 too.
5. The token is signed in main and returned to the worker, which answers it. The worker answers a refused frame
   403 `M_FORBIDDEN`.

### A user of another server subscribes only

* Its token has `canPublish` and `canPublishData` false: MSC4195 lets a server restrict publishing for users of other
  servers, and this one's SFU carries only its own users' media.
* No `CreateRoom` call is made for it. MSC4195 says the receiving server "creates the room (if needed)". This server
  does not, so that a request from another server never makes it call LiveKit.
* Nothing is lost by skipping the call. A subscriber has nothing to receive until a local user publishes, and that
  user's own request creates the room. LiveKit's `auto_create` (on by default) covers the order where the subscriber
  connects first.

### Outbound: a client names another server

When `server_name` is not this server's, `issue_client_livekit_token`:

1. Requires the caller joined here (the same 403 as for this server's SFU).
2. Requires the named server to have a member joined by this server's roster (`RoomMembers::has_member_of_server`),
   else 403 `M_FORBIDDEN` (MSC4195).
3. Takes an ADR-0079 slot (429 without one) and one deadline of 10 seconds, clamped by `remote_timeout`.
4. Sends `{member_id, room_id, slot_id, url, user_id}` over signed federation (`perform_outbound_call`,
   `OutboundAnswerTrust::unverified`, at most 8 KiB of answer) to the stable path only, with `runtime.mutex` released
   for the call.
5. Relays a 403 `M_FORBIDDEN` and a 400 `M_INVALID_PARAM` with this server's own text, never the other server's
   (MSC4195: upstream answers are not shown to clients). Anything else is 502 `M_UNKNOWN`.
6. Passes on only a `jwt` string that is three non-empty base64url segments of at most 4096 bytes. Its claims are the
   other server's to vouch for; this server does not read them.

The `url` is the other server's to judge and is never fetched here.

### Bounds and logging

* The inbound route is limited per verified origin by `security.federation.per_origin_request_rate`, as every
  federation endpoint but `/send` is.
* It costs one secret read and one signature, with no network call.
* The outbound relay is the client route's own per-user limit (ADR-0829) and the ADR-0079 budget.
* The `livekit` logger records:
  * `livekit.federation.issued` (`origin`, `user_id`, `room_id`);
  * `livekit.federation.refused` (with `reason`);
  * `livekit.relay.issued` (with `server_name`);
  * `livekit.relay.refused`;
  * `livekit.relay.failed`.

  It never records the token or the member ID.

### Positive Consequences

* A federated call works with the secret and the signing in main only, and every judgement is made by the server
  holding the room state.

### Negative Consequences

* A remote user cannot publish on this server's SFU. A deployment where users of several servers share one SFU
  needs each server to run its own.
* No server is known to serve the federation route yet, so the outbound relay has been tested only against this
  server.

## Pros and Cons of the Options

### Answer the inbound route in main without the worker (`federation_request_should_bypass_worker`)

* Good, because no frame or permit is needed.
* Bad, because the owner asked for the ADR-0595 relay. Inbound federation is routed by the worker, and main admits
  only what a permit binds.

### Issue remote users publishing tokens and create the room for them

* Good, because it follows MSC4195's default (SHOULD).
* Bad, because another server could then make this server call LiveKit and put media on its SFU.

## Links

* Refines [ADR-0829](0829-the-built-in-livekit-token-service-issues-tokens-only-to-users-this-server-finds-joined.md)
* [ADR-0595](0595-bind-worker-key-claim-and-query-relays-to-the-verified-request-by-digest.md)
* [ADR-0078](0078-the-federation-worker-never-signs.md)
* [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
