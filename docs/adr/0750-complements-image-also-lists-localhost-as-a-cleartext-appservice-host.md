# Complement's image also lists localhost as a cleartext appservice host

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestJoinFederatedRoomFromApplicationServiceBridgeUser` and
`TestJumpToDateEndpoint` failing against the 1.0.1 package

## Context and Problem Statement

[ADR-0515](0515-appservice-cleartext-http-only-to-loopback-literals-or-listed-hosts.md) accepts an
`http://` appservice URL only to a loopback IP literal or to a host listed in
`appservice.allow_cleartext_hosts`, and records that Complement's image lists `host.docker.internal`
alone. Complement's `hs_with_application_service` blueprint registers its appservice at
`http://localhost:9000`. `localhost` is a name, not a literal, so the registration was refused when the
server started and the appservice's `as_token` was answered 401. Every test built on that blueprint
failed before it reached what it tests. Should the image list `localhost` too?

## Decision Drivers

* Complement must exercise the appservice API, not the registration loader.
* The server's rule must not change for this: a cleartext name is always an operator's written choice.
* Inside the Complement container, `localhost` is the container's own loopback.

## Considered Options

* List `localhost` in the Complement image's `appservice.allow_cleartext_hosts`.
* Treat the name `localhost` as loopback in the server.
* Record the blueprint's tests as expected failures.

## Decision Outcome

Chosen option: list `localhost` in the image, as `host.docker.internal,localhost`. Only
`tests/complement/merovingian.conf.template` changes. The default stays empty, and the server still
decides from the URL text alone, so ADR-0515's rule is unchanged. ADR-0515's sentence naming the image's
setting is amended by this record.

### Positive Consequences

* The blueprint's registration loads, so its tests reach the behaviour they check.

### Negative Consequences

* The test image's list is longer than the one host the bundled appservices use. It is a test
  configuration, and its tooling test pins the exact list.

## Pros and Cons of the Options

### Treat `localhost` as loopback in the server

* Bad, because ADR-0515 refuses it on purpose: a name is resolved through configuration that can change,
  and the rule must be decided from the URL text alone.

### Record the tests as expected failures

* Bad, because the server is not wrong, and the tests would never check the appservice API.

## Links

* Amends [ADR-0515](0515-appservice-cleartext-http-only-to-loopback-literals-or-listed-hosts.md)
