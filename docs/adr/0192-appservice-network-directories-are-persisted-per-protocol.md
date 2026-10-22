# Appservice network directories are persisted per protocol, and instance IDs name the protocol

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit wave 3, "Additional endpoint and feature gaps":
`PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` was absent, and
`POST /publicRooms` ignored `third_party_instance_id` and `include_all_networks`.

## Context and Problem Statement

The Application Service API lets an appservice "maintain [its] own published room directories for [its]
defined third-party protocols", and clients read them through `third_party_instance_id` and
`include_all_networks` on `POST /publicRooms`. The homeserver's own directory is one boolean per room
(`rooms.directory_public`, ADR-0099) and cannot say which network a room is listed under, or by whom.

The spec names the key in two places that do not obviously agree. `networkId` is "the protocol
(network) ID to update the room list for ... provided by the application service as being listed as a
supported protocol". `third_party_instance_id` is "the `instance_id` of a `Protocol Instance` returned by
`GET /thirdparty/protocols`" (the homeserver mints `instance_id` itself, so a client can only echo it
back), and the example in the spec is `irc-freenode`. A registration may declare several protocols, and
the minted `instance_id` was `<registration id>:<instance index>`: two protocols of one registration
therefore both minted `bridge:0`.

The spec gives no failure status for the PUT.

## Considered Options

* A table `appservice_directory (appservice_id, network_id, room_id)`, with `network_id` the protocol
  name, and an `instance_id` that names the protocol
* Overload `rooms.directory_public` (a text column) with a list of networks
* Keep the listing in memory only, rebuilt by the appservice on every start
* Treat `networkId` as the `network_id` of a protocol *instance* (a Synapse reading), which needs a call to
  the appservice to discover

## Decision Outcome

Chosen option: the table, keyed by the protocol name, with a protocol-bearing `instance_id`.

* **Table (migration 025).** One row per `(appservice_id, network_id, room_id)`, main-process only, loaded
  at start into `PersistentStore::appservice_directory`, written through
  `set_appservice_directory_entry` (idempotent either way). It is independent of `rooms.directory_public`:
  being in a network's directory does not publish the room to the homeserver's own, and the reverse.
* **`networkId` is a protocol name the calling registration declares.** "Listed as a supported protocol"
  is read as a requirement. An undeclared protocol is `404 M_NOT_FOUND`, the status the third-party
  routes already use for an unknown protocol. Bridges that never declared a protocol have no network
  directory, which is correct: there is no network to list under.
* **`instance_id` is `<registration id>:<protocol>:<index>`, each of the first two percent-encoded.**
  Encoding makes the colons unambiguous; including the protocol makes the id unique across a
  registration's protocols and lets `third_party_instance_id` resolve to the exact `(appservice,
  protocol)` directory without asking the appservice. An id that matches no declared pair lists nothing
  (a network with no rooms) rather than falling back to the homeserver's own directory.
* **Fail-closed access rules.** Only a request authenticated with an `as_token` may publish
  (`403 M_FORBIDDEN` otherwise), and the appservice must have an interest in the room
  (`registration_interested_in_room_event`: a `rooms` or `aliases` namespace match or one of its users in
  it). Without that, a compromised or careless appservice could put the name, topic and avatar of any
  private room into a public directory. A room that does not exist is `404`.
* **publicRooms semantics.** Without the two parameters, the homeserver's own directory, as before.
  With `third_party_instance_id` only that network's rooms. With `include_all_networks: true` the
  homeserver's directory plus every network's, each room once. Both together are `400 M_INVALID_PARAM`
  ("Can only be used if `include_all_networks` is false"). A remote `?server=` lookup forwards both
  fields in the body of `POST /_matrix/federation/v1/publicRooms`. This server does not itself serve
  that federation endpoint (a separate gap), so the network filters are applied to local listings and
  forwarded for remote ones.

### Positive Consequences

* The published directory survives a restart, and rooms appear under exactly the network that listed them.
* Protocol-bearing instance IDs fix the collision between protocols of one registration.

### Negative Consequences

* A schema migration (025) and a new in-memory mirror.
* Instance IDs minted before this change (`bridge:0`) no longer resolve. They were never usable for
  anything, since nothing consumed them.
* A bridge that wants a network directory must declare the protocol in its registration file.

## Pros and Cons of the Options

### Overload `rooms.directory_public`

* Good, because there is no migration.
* Bad, because the value would have to encode appservice, network and room membership in a column every
  directory reader treats as `'true'`/`'false'`; any reader that is not updated mis-reads it.

### In memory only

* Good, because it is simple.
* Bad, because a restart empties every network directory until each bridge notices and re-publishes.

### Instance-level `network_id`

* Good, because it matches another implementation's keys.
* Bad, because the homeserver would have to call the appservice (an outbound request on the PUT) to learn
  which instance a `networkId` is, and the spec text says the id is a protocol ID.

## Links

* Spec: `docs/matrix-v1.19-spec/application-service-api.md`, "Published room directories"; client-server
  API `POST /publicRooms`; "Third-party Lookups" (`instance_id`)
* [ADR-0099](0099-default-unrecorded-directory-publication-private.md) for the homeserver's own directory
* `migrations/025_appservice_directory.sql`
