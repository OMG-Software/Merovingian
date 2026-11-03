# A key backup version number is never reissued, and deleting a version deletes its sessions

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-60

## Context and Problem Statement

`DELETE /room_keys/version/{version}` removed only the `key_backup_versions` row and its mirror entry. The version's
`key_backup_sessions` rows stayed in the database and in memory, though the spec deletes "all key data related to the backup".
`POST /room_keys/version` took the number of the highest surviving numeric version plus one, so deleting the highest version
freed its number, and the next backup inherited the old ciphertext: it reported the old count, and a stale row that was verified
or had a lower `first_message_index` made the server keep the old key (encrypted to the old backup key) and answer 200 to the
client's new upload.

## Considered Options

* Delete the sessions with the version in one transaction, add `ON DELETE CASCADE`, and issue numbers from a persisted per-user high-water counter
* Delete the sessions only; keep issuing max-plus-one
* Never delete a version row, only mark it deleted

## Decision Outcome

Chosen option: "delete the sessions in the same transaction, cascade, and a persisted counter", because each part closes a
different way the old ciphertext could come back.

* `database::delete_key_backup_version` commits `DELETE FROM key_backup_sessions` and `DELETE FROM key_backup_versions` in one
  transaction, and only then erases both from the in-memory mirror. `key_backup_sessions` also has
  `FOREIGN KEY (user_id, version) REFERENCES key_backup_versions (user_id, version) ON DELETE CASCADE`, so a version row removed
  by any other path takes its sessions with it. SQLite connections run with `PRAGMA foreign_keys = ON`.
* `database::create_key_backup_version` chooses the number: one past the larger of the user's `key_backup_version_counters` row
  (`PersistentStore::key_backup_version_high_water`) and every numeric version still held. It writes the counter and the version
  row in one transaction. A number is never issued twice, so a missed cleanup could not resurface old data under a new backup.
* The counter is a new table, `key_backup_version_counters (user_id, last_version)`, created in the v1 schema (no upgrade, ADR-0224).

### Positive Consequences

* A deleted backup's keys are gone from the database and from memory, and a new backup starts with no sessions.
* A client still holding the old version number cannot be given another backup's keys under it.

### Negative Consequences

* Deleting a version scans the sessions mirror once under `runtime.mutex`, as `delete_all_key_backup_sessions` already does.
* A counter row is kept for every user who has ever created a backup.

## Pros and Cons of the Options

### Delete the sessions only

* Good, because it needs no new table.
* Bad, because any later path that drops a version row, or a failed cleanup, brings the old keys back under a reissued number.

### Mark a version deleted

* Good, because the number could never be reused.
* Bad, because the ciphertext would stay on disk, against the spec.

## Links

* Related to [ADR-0224](0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md)
