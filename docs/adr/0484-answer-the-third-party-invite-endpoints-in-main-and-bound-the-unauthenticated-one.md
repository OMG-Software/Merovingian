# Answer the third-party invite endpoints in main, and bound the unauthenticated one

* Status: accepted
* Date: 2026-11-04

Technical Story: November project analysis, SS2

## Context and Problem Statement

Server-Server API v1.19, "Third-party invites", has two endpoints: `PUT /3pid/onbind`, called by an identity server on the
bound user's homeserver ("Requires authentication: No"), and `PUT /exchange_third_party_invite/{roomId}`, called by the
invited user's homeserver on the inviting one (authenticated with X-Matrix). Both were unserved, so a third-party invite
could never become a real invite. Where do they run, given the federation worker has no signing key and the unauthenticated
endpoint can be called by anyone on the Internet?

## Decision Drivers

* The exchange composes and signs an `m.room.member` event for this server, and may sign and send an `/invite` to the
  invitee's server. Only main holds the signing key (ADR-0078).
* `onbind` has no caller identity. Everything in its body is the caller's claim, and each valid invite in it can cost an
  outbound signed request to a server the caller names.

## Considered Options

* Relay both through new worker IPC frames, as `invite_ingest` is
* Answer both in main, without a worker
* Refuse `onbind` unless it comes from an identity server the operator trusts

## Decision Outcome

Chosen option: "answer both in main".

* The exchange is a normal authenticated route (`FederationEndpoint::exchange_third_party_invite`, ACL-checked by room),
  but `federation_request_should_bypass_worker` sends it to main after main verified the X-Matrix signature, as it does
  media downloads. A worker has no `third_party_invite_exchanger`, so were one to see it, it would answer 501.
* `onbind` is matched by exact path in `FederationProxy::handle` and `handle_federation_http_request` before any
  signature is demanded, like `openid/userinfo` and `version`. There is no IPC frame for it.
* What `onbind` can cost is bounded in `notify_third_party_bind`: the body is parsed with at most
  `max_third_party_bind_invites` (32) invites, an entry that is malformed or names a user other than the bound `mxid` is
  dropped, the whole request draws one slot of the ADR-0079 outbound budget keyed by the caller's address
  (`rate_limit_client_key`, 429 when spent) and one 30 second deadline, and nothing is done for a user who is not an active
  account here (the answer is the same, so it is no account oracle). Nothing in the body is believed: the signature on each
  `signed` is checked by whichever server holds the room, against the keys of the room's own `m.room.third_party_invite`
  (ADR-0485), never against anything the caller supplies.
* The `key_validity_url` of the invite's public keys is not fetched. The spec's exchange does not ask for it, and fetching
  a URL a room member chose from an unauthenticated trigger would be a request-forgery channel.

### Negative Consequences

* No operator allowlist of identity servers: a valid `onbind` for a user who never bound anything is still processed. It
  can do no more than the identity server's own signed object allows.
* A request to `onbind` can make this server send up to 32 signed requests. The outbound slot and the per-address share
  limit that, not the endpoint.

## Links

* [ADR-0078](0078-the-federation-worker-never-signs.md) (the worker never signs)
* [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* [ADR-0485](0485-an-exchanged-third-party-invite-is-issued-by-the-sender-s-server-for-the-caller-s-own-user.md)
