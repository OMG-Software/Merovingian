# The OAuth 2.0 API is built into the homeserver

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

Technical Story: Element X cannot create an account on Merovingian. It reports that the account provider "needs to
be upgraded to support Matrix Authentication Service and account creation".

## Context and Problem Statement

Element X creates accounts only through the Matrix OAuth 2.0 API, which the spec added in v1.15 beside the legacy
login and registration API. Merovingian answered the discovery request, `GET /_matrix/client/v1/auth_metadata`, with
`404 M_UNRECOGNIZED` unless `server.oidc.*` was set, and those keys only published the addresses of an authorisation
server run by someone else. Merovingian could not accept a token such a server issued.

Who is the authorisation server for a Merovingian deployment?

## Decision Drivers

* An operator should get a working Element X from one package and one configuration file.
* The authorisation server decides who may hold a session. That is the most security-sensitive decision the
  homeserver makes, and the project's rules for tokens, passwords and throttling already govern it.
* The spec defines the OAuth 2.0 API as something a homeserver offers. It defines no protocol between a homeserver
  and a separate authorisation server.

## Considered Options

* Build the OAuth 2.0 API into the homeserver.
* Delegate to Matrix Authentication Service.
* Keep publishing an operator-supplied authorisation server's metadata.

## Decision Outcome

Chosen option: "Build the OAuth 2.0 API into the homeserver". The homeserver serves the metadata, client
registration, the authorisation, token and revocation endpoints and the pages the user sees. A session it issues is
an ordinary session in the existing session and token tables.

### Positive Consequences

* One process holds accounts, sessions and tokens. Revocation, deactivation, locking and the device cap apply to an
  OAuth session exactly as they apply to a legacy one.
* No second service to package, configure, secure and upgrade.

### Negative Consequences

* The homeserver now serves HTML pages to a browser. That is new attack surface, which
  [ADR-0815](0815-the-authentication-pages-are-built-into-the-binary-without-javascript.md) bounds.
* Upstream identity providers (signing in with an account held elsewhere) are not part of this decision and are not
  provided.

## Pros and Cons of the Options

### Delegate to Matrix Authentication Service

* Good, because the pages, the flows and the upstream-provider support already exist.
* Bad, because the homeserver side is not in the spec: it is a private interface (token introspection and an
  account-provisioning API) that Matrix Authentication Service defines for Synapse.
* Bad, because every deployment would need a second service and a second database.

### Keep publishing an operator-supplied authorisation server's metadata

* Bad, because it cannot work: a client that follows the metadata receives a token Merovingian does not recognise.

## Links

* Refined by [ADR-0813](0813-the-legacy-authentication-api-stays-on-by-default-and-a-config-key-turns-it-off.md),
  [ADR-0814](0814-the-registration-page-applies-the-legacy-registration-settings.md),
  [ADR-0815](0815-the-authentication-pages-are-built-into-the-binary-without-javascript.md) and
  [ADR-0816](0816-server-oauth-replaces-server-oidc-and-the-old-keys-are-refused.md)
