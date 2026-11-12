# A key backup's etag comes from an incremental content digest, and a backup session has a size limit

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C22, `key_backup_etag` rehashing every stored byte of a backup version per request

## Context and Problem Statement

Every `GET /room_keys/version[/{v}]` and every `PUT /room_keys/keys[...]` answered with the backup's `etag`, computed by
collecting, sorting and BLAKE2b-hashing every stored session of the version, with `runtime.mutex` held. A session was limited
only by the 1 MiB body, so the work grew with the bytes a user had stored. The spec says the etag is "an opaque identifier
describing the current contents of the backup, which can be used to detect if the contents have changed". How is the etag kept
cheap without losing that property or changing across a restart?

## Considered Options

* An order-independent digest of the sessions, kept by every writer and rebuilt on load
* A persisted counter per version, bumped by every write
* Keep the full hash and only cap the stored bytes
* A cached etag invalidated on write

## Decision Outcome

Chosen option: "An order-independent digest of the sessions, kept by every writer and rebuilt on load".

`PersistentStore::key_backup_digests` holds, per (user, version), a `KeyBackupDigest`: the number of sessions and the sum, per
64-bit limb, of the BLAKE2b hash of each session (room ID and session ID length-prefixed, then the JSON). The sum does not depend
on order, so a session added, replaced or removed changes it by that session's hash alone: `append_backup_session`,
`replace_backup_session_json` and `erase_backup_session_at` are the only places a session row appears, changes or goes, and each
moves the digest. `key_backup_etag` hashes the version and the digest, so a request reads no session. The digest is a function of
the content, so the etag is the same after a restart (hydration calls `rebuild_key_indexes`, which rebuilds the digests in one
pass) and returns to an earlier value if the content does. A digest is trusted only while its count equals the version's
session count; a writer heals it from the rows before applying its delta, and the const reader recomputes without storing the
result (ADR-0525).

A session over `max_uploaded_key_document_bytes` (16 KiB, the limit of every other uploaded key document) is `400 M_TOO_LARGE` with
nothing stored, for the single-session, room and batch PUTs, judged on the stored form. A real session is a few hundred bytes.

### Rejected: a persisted counter

It needs a migration (the schema is frozen since 1.0.0), and a counter changes on every write even when the content is the same,
which makes a client re-download a backup it already has.

### Rejected: the cap alone

It bounds the bytes but not the per-request pass over up to `max_key_backup_sessions_per_user` sessions (about 1.4 s at 500,000
sessions in the audit's debug build).

### Rejected: a cached etag invalidated on write

Every writer would have to remember to invalidate, and a missed one serves a stale etag, the failure the spec forbids. The digest
cannot be stale in that way: the writers change the row and the digest in one place.

### Negative Consequences

* A user's stored backup bytes are bounded by the session size limit times `max_key_backup_sessions_per_user` (operator-set,
  500,000 by default); there is no separate per-user byte total.
* `GET /room_keys/keys` still serialises the whole version or room, as the spec requires; with the size limit its response is
  bounded by the session count and limit.
