# The encryption settings apply to room creation only

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`block_unencrypted_federated_private_rooms` and the docs claimed more than creation: refusing joins of, or ingest of, rooms other servers created as unencrypted.

## Considered Options

* Also refuse joins and federation ingest of unencrypted private rooms
* Creation only

## Decision Outcome

Chosen option: creation only, by owner decision. Joining a room another server created, or ingesting its events, is never refused for its encryption. The user manual, the example config and the Complement template say so. Revisit only as a new ADR; refusing joins would need a spec-conformant error and its own interoperability tests.
