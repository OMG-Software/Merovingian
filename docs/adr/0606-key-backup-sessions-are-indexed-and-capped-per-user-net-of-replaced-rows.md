# Key backup sessions are indexed and capped per user, counting only what a request adds

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.key-backup.batch-upload-quadratic-under-mutex-no-session-quota`

## Context and Problem Statement

`PUT /room_keys/keys` with about 100000 tiny sessions scanned the whole `key_backup_sessions` vector twice per session
(once to see whether a held key wins, once to store it, over a vector that grew during the batch), so one request from
any account held the runtime lock for minutes. The number of sessions and versions a user could keep was unbounded, and
the count and etag in each answer were recomputed by walking the whole table. How are backups indexed, and what limits
apply?

## Decision Drivers

* Real backups reach six figures of sessions, so the cap must not refuse an honest client.
* A client re-uploads a whole backup, so replacing a held session must never be refused.
* The refusal must happen before any write.

## Considered Options

1. Cap only, leave the scans.
2. Index sessions by (user, version) and by (user, version, room, session), count and etag from the index, and cap.
3. One cap per version.

## Decision Outcome

Chosen option 2.

* `key_backup_session_index` (`RowKeyIndex`) finds one session; `key_backup_version_session_index` and
  `key_backup_user_version_index` (`RowGroupIndex`) list a version's sessions and a user's versions. A session erase moves
  the last row into the gap (ADR-0605). `count_key_backup_sessions` reads the group's count. The etag and the GET
  routes walk only the version's own sessions.
* `max_key_backup_sessions_per_user` (default 500000, 1..100000000) counts the user's sessions across all their versions.
  `max_key_backup_versions_per_user` (default 100, 1..10000). Both are refused with 400 `M_TOO_LARGE` before any write.
* A PUT (whole batch, per room or per session) counts only the sessions it would add: a (room, session) already held in
  that version is replaced or deliberately kept, and either way adds nothing, so re-uploading a backup at the cap works.
  A batch that adds even one over the cap is refused whole and stores none of it.

### Rejected: a cap per version

A user could create versions to multiply the cap; the per-user total across versions, with its own version cap, bounds both.

### Negative Consequences

* A user at the session cap must delete sessions or a version to add new ones; nothing is evicted.
* Deleting a version rebuilds the small version index (at most the versions held) and erases the version's sessions one by
  one at O(1) each.
