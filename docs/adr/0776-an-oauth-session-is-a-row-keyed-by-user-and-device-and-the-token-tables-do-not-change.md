# An OAuth session is a row keyed by user and device, and the token tables do not change

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 3 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), proposal P3

Amended by [ADR-0808](0808-an-oauth-session-row-ends-with-the-last-credential-of-its-device.md): a session row is also
deleted, in the same transaction, wherever every token of its device is revoked, and by the retention sweep once its
device holds no live token.

## Context and Problem Statement

The OAuth 2.0 API needs to know which devices were created by an OAuth grant, with which client and which scope, so
that the token endpoint can refuse a legacy refresh token for an OAuth device (and the reverse), the revocation
endpoint can end the session, and retention can tell a client with a session from one without. Where is that fact
stored?

## Decision Drivers

* The v1 tables are frozen since 1.0.0 (ADR-0224): a schema change is a new migration, and an `ALTER TABLE` on a
  frozen table changes the shape 1.0.x wrote.
* Some inserts into `access_tokens` and `refresh_tokens` are positional (`INSERT INTO access_tokens VALUES (...)`), so a
  new column on those tables would change every one of them.
* A device is an OAuth device or it is not. Every token of the device shares that fact, so it belongs to the device,
  not to each token.
* The spec forbids deleting a client registration that has an active session, so the store must answer "does this
  client have a session" without scanning tokens.

## Considered Options

* A new `oauth_sessions` table keyed by (`user_id`, `device_id`), with `client_id`, `scope` and `created_at_ms`.
* A `client_id` (and scope) column on `access_tokens` and `refresh_tokens`.
* A column on `devices`.

## Decision Outcome

Chosen option: the `oauth_sessions` table, created by migration 002 together with `oauth_clients` and an index on
`oauth_sessions (client_id)`. The token tables are not changed. The row is written by the caller's own transaction
(`prepare_oauth_session_insert`, then `commit_persistent_transaction` with the device and token inserts, then
`remember_oauth_session`), and `delete_device` deletes it in the transaction that deletes the device, so the two
cannot disagree. Neither table has a foreign key: no table of the v1 schema declares one, and `delete_device`
already removes every dependent row explicitly in one transaction.

### Positive Consequences

* No frozen table changes shape; a 1.0.x database gains two empty tables and nothing else.
* "Is this an OAuth device" and "does this client have a session" are one hash lookup each in memory.
* Every path that deletes a device removes the session row with it, because every one goes through `delete_device`.

### Negative Consequences

* A new path that deletes a `devices` row without `delete_device` would leave a session row behind. The rule is
  written in `src/database/AGENTS.md`.

## Pros and Cons of the Options

### A column on the token tables

* Good, because a token lookup would carry the client at once.
* Bad, because it is an `ALTER TABLE` on frozen v1 tables and changes every positional insert.
* Bad, because a device's tokens would each repeat the same fact, and a refresh rotation could split them.
* Bad, because "does the client have a session" would scan tokens.

### A column on `devices`

* Good, because the fact sits on the device.
* Bad, because it is still an `ALTER TABLE` on a frozen table, and `insert_device` is positional.

## Links

* Builds on [ADR-0224](0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md)
* Related to [ADR-0777](0777-an-oauth-client-s-last-use-is-written-at-most-once-a-day.md) and
  [ADR-0778](0778-the-schema-is-built-from-per-version-tables-and-each-migration-step-from-what-its-version-adds.md)
