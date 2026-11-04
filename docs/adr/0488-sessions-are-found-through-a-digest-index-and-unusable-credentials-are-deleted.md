# Sessions are found through a digest index, and credentials that cannot authenticate are deleted

* Status: accepted
* Date: 2026-11-04

Technical Story: November analysis P7 and G7.

## Context and Problem Statement

`find_session` scanned every `LocalSession` for every authenticated request, under `runtime.mutex`, and nothing ever
erased a session: revoked and expired rows stayed in memory (and in `access_tokens` and `refresh_tokens`) for ever, so
the scan only grew. `src/auth/AGENTS.md` rule 3 requires token hashes to be compared with `constant_time_equal`.

## Considered Options

* Key an `unordered_map` on the full hash string.
* Keep the vector and add an index from a digest of the hash to the session's position; confirm every candidate with
  the existing constant-time comparison.
* Sort the vector and binary-search it.

## Decision Outcome

The second option, as `homeserver::SessionTable` (`LocalDatabase::sessions`). The digest is `std::hash` of the stored
hash, which is a uniformly distributed BLAKE2b output (keyed for v3 and v4), so a client that holds only a bearer token
cannot steer a bucket. The index compares digests only; the match itself is still `token_hash_matches`
(`constant_time_equal`), so nothing about the comparison rule changed. A map keyed on the string would compare hashes
with `==`, which rule 3 forbids. A sorted vector needs an ordering comparison, which is not constant time either.

A hash written to a session behind the index's back is found by nothing (the candidate is confirmed against the real
hash), so a stale index fails closed. `set_access_token_hash` is the one writer (the v3 to v4 upgrade).

Unusable credentials are deleted by the `retention-sweep` job (`run_retention_sweep`):

* An access token is unusable once revoked (one-way, ADR-0052) or once it has been expired for seven days. The grace
  keeps the audit reason `token expired` (rather than `session not found`) for a week; a revoked token carries no such
  diagnostic and goes at once.
* A refresh token is unusable once it has expired. A refresh token that is revoked but not yet expired is KEPT:
  presenting it is how a rotated, stolen token is detected (ADR-0074). Deleting it would turn that detection into a
  plain 401 that leaves the new session alive. An expired one is refused before the reuse check, so deleting it changes
  no answer.

The database is deleted in transactions of at most 500 rows, `runtime.mutex` is released between them, and memory is
erased once at the end of the sweep, only for hashes the database really deleted.

## Consequences

* An authenticated request's session lookup costs the candidates in one bucket, not the number of sessions.
* Other code that walks `sessions` (logout, revoke by device) still scans; those are not on every request.
* Do not replace the confirm step with the index hit, and do not write `access_token_hash` through an iterator.
