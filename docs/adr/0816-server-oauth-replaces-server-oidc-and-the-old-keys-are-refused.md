# `server.oauth.*` replaces `server.oidc.*`, and the old keys are refused

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

`server.oidc.*` made `GET /_matrix/client/v1/auth_metadata` publish the endpoints of an authorisation server the
operator named. Merovingian implemented none of the flow and accepted no token from that server, so a client that
followed the metadata could not log in. With the OAuth 2.0 API built in
([ADR-0812](0812-the-oauth-2-0-api-is-built-into-the-homeserver.md)) the metadata describes this server and is
generated. What becomes of the old keys?

## Considered Options

* Replace them with `server.oauth.*` and refuse a configuration that still sets them.
* Keep them beside `server.oauth.*`, mutually exclusive.
* Ignore them with a warning.

## Decision Outcome

Chosen option: "Replace them with `server.oauth.*` and refuse a configuration that still sets them".
`server.oauth.enabled` turns the built-in server on. The issuer and every endpoint address are derived from
`server.public_baseurl`; none is configured. A configuration that sets any `server.oidc.*` key fails validation at
start-up with a message that names `server.oauth.enabled`.

### Positive Consequences

* The metadata cannot disagree with what the server serves, because one function produces both.
* An operator who had set `server.oidc.*` learns at start-up that it did nothing, instead of the server silently
  advertising a different authorisation server from before.

### Negative Consequences

* A 1.0.x configuration that sets `server.oidc.*` does not start on 1.1.0 until the keys are removed. The release
  notes say so. The keys never produced a working login, so no working deployment depends on them.

## Pros and Cons of the Options

### Keep them beside `server.oauth.*`

* Bad, because it keeps a setting whose only effect is to advertise a login that cannot complete.

### Ignore them with a warning

* Bad, because a server that used to advertise an external authorisation server would start advertising none, or
  its own, with only a log line to say so.
