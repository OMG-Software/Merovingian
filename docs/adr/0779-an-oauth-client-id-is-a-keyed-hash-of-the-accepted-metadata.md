# An OAuth client ID is a keyed hash of the accepted metadata

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 4 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), proposal P2

## Context and Problem Statement

`POST /_merovingian/oauth2/register` is unauthenticated (the spec: "Client registration"), and a client may register
again on every start. Each registration that makes a row costs storage and counts against the registration cap
(ADR-0780). What client ID does a registration get?

## Decision Drivers

* A client that registers again with the same metadata must not cost a new row, or one app's restarts fill the table.
* An ID must not let anyone who knows a client's metadata predict its ID on this server without the server's key, so
  IDs of one server say nothing about another and cannot be precomputed against a leaked metadata list.
* The ID travels in a query string, a form body and a log line: it must need no escaping in any of them and fit
  `database::max_oauth_client_id_bytes` (128).

## Considered Options

* A keyed hash of `ClientMetadata::canonical_bytes()`.
* A random ID per registration.
* An unkeyed hash of the canonical metadata.

## Decision Outcome

Chosen option: a keyed hash. The ID is the unpadded URL-safe base64 of the 32-byte keyed BLAKE2b digest of the
canonical metadata (`crypto::oauth_client_id`, 43 characters of `A-Z a-z 0-9 - _`). The key is derived from the master
key with its own label, `merovingian:oauth-client-id:1` (`crypto::derive_oauth_client_id_key`), the way the access-token
keys are, and is cached with them in `TokenHmacKeys` from one read of the master key file. Canonical bytes make the
ID independent of key order, repeated list entries and ignored members, so a repeat registration finds its row and only
touches its last use (at most one write a day, ADR-0777).

### Positive Consequences

* A client's restarts cost no row and, within a day, no commit.
* A client ID cannot be computed without the master key, and changing the master key changes every ID.

### Negative Consequences

* Two installs of one app with identical metadata share a client ID. Nothing in the API binds a secret to it
  (`token_endpoint_auth_method` is `none`), so the shared ID gives neither install anything over the other.
* Replacing the master key orphans every registered client; clients register again, as the spec allows.

## Pros and Cons of the Options

### A random ID per registration

* Good, because the ID reveals nothing about the metadata.
* Bad, because every restart of every client makes a row, so the cap is reached by ordinary use and eviction becomes
  routine instead of the exception.

### An unkeyed hash

* Good, because it needs no key.
* Bad, because anyone can compute a client's ID from its metadata, the same on every server.
