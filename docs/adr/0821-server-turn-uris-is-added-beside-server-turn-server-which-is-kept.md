# server.turn.uris is added beside server.turn.server, which is kept

* Status: accepted
* Date: 2026-11-16

## Context and Problem Statement

`GET /voip/turnServer` answers `uris`, "a list of TURN URIs" (Matrix v1.19, Voice over IP), but the configuration held
one URI, `server.turn.server`. An operator normally runs a UDP and a TCP or TLS relay, and a client behind a firewall
that blocks UDP needs the second one. How does the configuration name several URIs without breaking a 1.0.x file?

## Decision Outcome

Chosen option: "a new list key beside the old one", because a 1.0.x configuration must still parse in 1.1 and the old
value keeps its meaning.

* `server.turn.uris` is a comma-separated list (as `server.identity_server.trusted_servers` is). The response's `uris`
  array carries the entries in the configured order. `server.turn.server` stays, and still gives a one-element array.
* TURN is enabled when either key is set. Setting both is refused at parse time, like `shared_secret_file` with
  `username` and `password`, so it is never unclear which one clients get.
* Each `server.turn.uris` entry is refused, never repaired, unless it starts with `turn:` or `turns:` followed by
  something, is at most 512 bytes of printable ASCII (no whitespace or control character), is not a repeat of an
  earlier entry, and the list holds at most 16 entries. `server.turn.server` has never been validated, and is not
  tightened here: a value an existing configuration holds must not start to be refused by an upgrade.
* The key is reloadable and diffed by the reload plan like the other `server.turn.*` keys.

## Pros and Cons of the Options

### Replace server.turn.server with the list

* Bad, because every 1.0.x configuration that sets it would stop working.

### Make server.turn.server accept a list

* Bad, because it changes the meaning of an existing value: a URI containing a comma would be split.

## Links

* Builds on [ADR-0480](0480-turn-credentials-come-from-a-coturn-shared-secret-file-through-an-openssl-hmac-sha1.md)
