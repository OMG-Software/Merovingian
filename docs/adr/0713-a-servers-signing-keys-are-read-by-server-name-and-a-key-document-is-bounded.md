# A server's signing keys are read by server name, and a remote key document is bounded

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

This server's own signing keys and every remote server's cached keys share one table. Each choice of "which key do I sign
with" copied that whole table and scanned it under `runtime.mutex`, and a remote server could add rows without limit: every
`old_verify_keys` entry became a stored row nothing deletes, and a server name that cost one fetch added them again. After
that, every local send and every `GET /_matrix/key/v2/server?x` (the query skipped the lock-free cache) paid a copy of the
table (run-3 finding C27).

## Considered Options

* Index the table by server name, read one server's rows, bound what one document may add, and match the key-server fast
  path without the query
* A separate small table for this server's own keys
* Prune retired remote rows by age
* A row cap per remote server name only

## Decision Outcome

Chosen option: "Index the table by server name". `server_signing_key_index` (a `RowGroupIndex` keyed on the server name)
is kept by the two writers of the vector and trusted only while it is in step with the row count, as the other table
indexes are (ADR-0603); a reader scans otherwise, so a load from the database costs speed, never correctness. The own-key
selection, the active-key collection, the `old_verify_keys` publication and `find_any_cached_remote_key` use
`snapshot_server_signing_keys_of`, whose work is that server's rows. `find_server_signing_key` and the secretless-write
check use the index too.

A remote key document is limited: more than 16 `verify_keys` refuses it, and `old_verify_keys` past 64 are not stored
(they judge older events only, and an honest server publishes a few). The key-server fast path in `HttpServer` matches the
path with `is_federation_key_server_endpoint`, so a query string no longer skips the cache.

Why not a separate table for own keys: the persisted table and its secret handling are shared, and splitting them moves
the write paths that ADR-0083 and ADR-0425 constrain. Why not pruning: a retired remote key is still needed to verify old
events, and the right horizon is a policy decision. Why not a row cap per server name alone: the attacker uses new names.

Residual: remote rows still grow by up to 80 per fetched server name, rate-limited by the unknown-source key-resolution
bucket. They are no longer copied or walked by anything on the signing path.
