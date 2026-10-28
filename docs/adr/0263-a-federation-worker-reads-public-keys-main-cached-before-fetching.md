# A federation worker reads public keys main cached before fetching

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (A6)

## Context and Problem Statement

A worker's key mirror is a start-up snapshot, and it cannot write the shared cache (ADR-0238). The first PDU from a server main had already verified made the worker fetch that key again, a TLS round trip in front of the PDU.

## Considered Options

* On a miss, re-read that server's public key rows from the database, then fetch
* Relay key resolution to main over IPC
* Let main send the key with the proxied request
* Give the worker write access
* An in-memory worker cache only

## Decision Outcome

Chosen option: "On a miss, re-read that server's public key rows from the database, then fetch", because the worker already trusts these columns for every server it knew at start-up, and only main writes them, after verifying the key and capping it at the spec's seven days. The read selects `server_name, key_id, public_key, valid_until_ts` only and never `secret_key` (the worker's PostgreSQL role is granted exactly those columns). Main still re-verifies every relayed PDU with its own resolver (ADR-0071). Only a worker runtime enables it.

### Positive Consequences

* No duplicate key fetch ahead of a server's first PDU once main knows the key.

### Negative Consequences

* The worker now reads the key table after start-up; the PostgreSQL path is not exercised by the unit suite.

## Links

* Refines [ADR-0238](0238-the-key-resolver-uses-the-key-it-fetched-not-a-cache-read-back.md)
