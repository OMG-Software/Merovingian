# Appservice cleartext http only to loopback literals or listed hosts

* Status: accepted; the setting of Complement's image is amended by [ADR-0750](0750-complements-image-also-lists-localhost-as-a-cleartext-appservice-host.md)
* Deciders: James Chapman
* Date: 2026-11-06

Technical Story: SonarCloud `cpp:S5332` on the `http://` literals in `src/appservice/AppserviceClient.cpp`

## Context and Problem Statement

An Application Service registration `url` could be `http://` to any host. The homeserver puts its
`hs_token` in the `Authorization` header of every request to that URL, and the response and request
bodies carry room events. Over plain http to a host reached across a network, anyone on the path can
read the token and then impersonate the homeserver to the appservice. Which `http://` destinations may
the server accept?

## Decision Drivers

* The `hs_token` and the events must not cross a network in cleartext by accident.
* The spec's own example (`http://127.0.0.1:1234`) and most bridges run beside the homeserver on
  loopback, and must keep working.
* Complement registers appservices at `http://host.docker.internal:<port>`, a name the container
  resolves to the host. That path never leaves the machine, but is not a loopback literal.
* The rule must not depend on DNS at request time, which an attacker who controls a name can change.
* SMTP already has a definition of "loopback" (ADR-0220); two definitions would drift.

## Considered Options

* Keep `http://` to any host.
* `http://` only to a loopback IP literal.
* `http://` to loopback literals or to addresses in private ranges, judged after DNS resolution.
* `http://` to a loopback IP literal, or to a host the operator lists by name.

## Decision Outcome

Chosen option: "a loopback IP literal, or a host the operator lists by name", because it keeps the
common case working, makes every other cleartext destination a deliberate operator choice that is
written in the configuration, and is decided from the URL text alone.

* A registration `url` with scheme `http` is accepted only when its host is an IPv4 dotted quad in
  127.0.0.0/8, an IPv6 literal equal to `::1` (`net::is_loopback_ip_literal`, shared with SMTP), or an
  exact, ASCII-case-insensitive match for an entry of `appservice.allow_cleartext_hosts` (comma
  separated, default empty). The name `localhost` is not a literal.
* `https` URLs are unchanged. A null `url` means no traffic and stays valid.
* A URL with userinfo, a query string, or a scheme other than http and https is refused. The spec lets
  the URL "include a path after the domain name"; a query is not part of it.
* The rule is applied twice: `appservice::load_registrations` rejects the registration (a per-file
  finding, no token in the text), and `AppserviceClient` refuses the call before any lookup or
  connection. The second check covers a registration that reaches the client without the first.
* Complement's image sets `appservice.allow_cleartext_hosts=host.docker.internal`.

### Positive Consequences

* A bridge on another machine cannot be reached over cleartext by a typo or a copy of an old example.
* The hs_token's exposure is bounded by a list the operator can read in one place.
* One definition of a loopback literal for SMTP and appservices.

### Negative Consequences

* An existing deployment with `http://bridge.internal:9000` fails to load that registration until the
  host is listed (or the bridge moves to https). The failure is a logged finding at start-up.
* Listing a host sends it the hs_token in cleartext; the operator carries that judgement.

## Pros and Cons of the Options

### Keep `http://` to any host

* Good, because nothing breaks.
* Bad, because the hs_token and events can cross a network in the clear, the thing the finding flags.

### Loopback IP literal only

* Good, because it is the smallest rule and needs no setting.
* Bad, because Complement and containerised bridges (a bridge in another container, reached by a name)
  stop working.

### Private ranges after DNS resolution

* Good, because it admits container networks without a list.
* Bad, because it depends on DNS at request time, so a name's answer can change after it was approved,
  and it is broader than needed: every host on a private network would qualify, including shared ones.

### Loopback literal plus an exact host opt-in list

* Good, because the permitted set is explicit, exact, and decided without DNS.
* Bad, because an operator must edit the configuration for each non-loopback cleartext bridge.

## Links

* Builds on [ADR-0220](0220-smtp-goes-through-libcurl-with-tls-required-except-to-a-loopback-literal.md)
  for the loopback-literal definition.
