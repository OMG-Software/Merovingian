# `response_mode=query` is accepted for an `https` redirect URI

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5b of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

Spec v1.19 "Authorisation code grant" says homeservers and clients MUST "use the `fragment` response mode ... for
clients with an HTTPS redirect URI", and "Login flow" says clients SHOULD use `fragment` when the redirect URI is an
`https` URI with a remote host, so the code does not reach the web server behind it. Should the authorisation endpoint
refuse `response_mode=query` (or an absent `response_mode`, which RFC 6749 makes `query`) when the redirect URI is
`https`?

## Decision Drivers

* The MUST is written for "homeservers and clients" together: it is the client that chooses the mode.
* Element X on iOS registers a claimed `https` redirect URI, and which mode it sends was not verified (the plan's open
  items under "What Element X needs"). Refusing would lock it out until a release of the client.
* The code is useless without the PKCE verifier, which only the client holds.

## Considered Options

* Accept `query` and `fragment` for every redirect URI; an absent `response_mode` is `query`
* Refuse `query` (and an absent mode) for an `https` redirect URI with `invalid_request`
* Answer in the fragment for an `https` redirect URI whatever the client asked

## Decision Outcome

Chosen option: accept both modes for every redirect URI, and read an absent `response_mode` as `query`. Only another
value is refused, with `invalid_request` in the query.

### Positive Consequences

* A client that sends `query` for a claimed `https` link still logs in.

### Negative Consequences

* For such a client the code reaches the server behind the redirect URI in its query, and its logs. PKCE keeps it from
  being redeemed by anyone else, and it lives 60 seconds.

## Pros and Cons of the Options

### Refuse `query` for an `https` redirect URI

* Good, because it holds clients to the spec's rule.
* Bad, because a client this server must serve may be locked out with no way for the user to recover.

### Answer in the fragment whatever was asked

* Bad, because a client reading the query would not find its code: repairing a request is what the module rules forbid.

## Links

* Revisit after phase 11 tests the flow with the real Element X clients
