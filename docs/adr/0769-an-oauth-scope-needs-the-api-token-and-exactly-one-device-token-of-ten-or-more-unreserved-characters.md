# An OAuth scope needs the API token and exactly one device token of ten or more unreserved characters

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

The spec ("Scope") defines `urn:matrix:client:api:*` and `urn:matrix:client:device:<device_id>`, requires exactly
one device token in the login flow, lets the client choose the device ID, and lets the server refuse a device ID
that is shorter than ten characters or holds characters outside RFC 3986's unreserved set. It does not say what a
scope without the API token, with the same device token twice, or with unknown tokens means.

## Considered Options

* Strict: refuse a scope without the API token, with no device token or more than one (even the same one twice),
  with a device ID outside `auth::device_id_is_valid`, shorter than ten or holding non-unreserved characters, and
  with any byte outside RFC 6749's scope-token set or any spacing but single spaces; drop unknown tokens; know only
  the stable token forms.
* Lenient: collapse repeated device tokens, accept any device ID the legacy API accepts, and also read the
  `org.matrix.msc2967` forms.

## Decision Outcome

Chosen option: "Strict". The granted scope is rebuilt in canonical order
(`urn:matrix:client:api:* urn:matrix:client:device:<id>`) from what was read, so tokens this server does not know
are never stored or echoed. The scope is capped at 2048 bytes and 32 tokens.

### Positive Consequences

* A device ID from the OAuth API is always safe as a path segment, a key ID suffix and a scope token, and long enough
  that two devices of one user do not collide by chance.
* Two device tokens can never leave the server and the client disagreeing about which device was allocated.

### Negative Consequences

* A client that uses only the unstable MSC2967 forms, or a short device ID, cannot log in. Element X uses the stable
  forms and a ten-character ID (`docs/todos/oauth-2-0-api.md`, "What Element X needs").
