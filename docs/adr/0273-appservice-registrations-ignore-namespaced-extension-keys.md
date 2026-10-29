# Appservice registrations ignore namespaced extension keys

* Status: accepted (refines [ADR-0035](0035-parse-appservice-registrations-as-a-bounded-yaml-subset.md))
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestJoinFederatedRoomFromApplicationServiceBridgeUser`,
`TestJumpToDateEndpoint`)

## Context and Problem Statement

ADR-0035 made every unknown key in a registration file a parse failure. Complement's
registrations, and those written by real bridges such as the mautrix family, carry keys outside
the specification: `de.sorunome.msc2409.push_ephemeral`, `org.matrix.msc3202`, and MSC2409's
unstable `push_ephemeral`. Such a file was refused, so the bridge could not be loaded at all.
The spec defines the registration fields and says nothing of unknown ones.

## Considered Options

* Keep every unknown key a parse failure (ADR-0035 as written).
* Ignore every unknown key, with a warning.
* Ignore only reverse-DNS namespaced keys and `push_ephemeral`, with a warning; keep every other
  unknown key a parse failure.

## Decision Outcome

Chosen option: ignore namespaced keys and `push_ephemeral` only, because those are the keys
real registrations carry, while a typo of a real key (`as_tokn`, `namespace`) still stops the
file from loading instead of loading a registration that silently lacks it.

* A namespaced key is lower case `[a-z0-9._-]` with at least one dot, not at either end: the
  spec's convention for keys outside the specification.
* An ignored key is logged at warning level (`registration.key_ignored`, logger `appservice`)
  naming the key. Its value is never read.
* `push_ephemeral` is not mapped onto `receive_ephemeral`: a bridge that wants ephemeral data
  sets the spec's key.
* The rest of ADR-0035 stands: anchors, aliases, tags, block scalars, tabs and document markers
  are still parse failures, and the bounds are unchanged.
