# A blob row is deleted with its last reference, and a removed record holds no reference

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `data-lifecycle.media-blobs.zero-ref-rows-never-reclaimed` and
`data-lifecycle.media-blobs.removed-remote-record-releases-shared-blob-twice`

## Context and Problem Statement

ADR-0094 kept a blob row at zero references, with its bytes cleared, so that a re-upload revived one identity. Nothing
ever deleted those rows, so each remote file that passed through the cache left a row in `repository.blobs`, in
`store.media_blobs` and in the database for good, and every blob lookup paid for them. Separately, an administrator's
removal marks a cached remote record `removed` and releases its blob, but leaves the record (and its cache entry) in
place so the removal is remembered; when that entry was later displaced the record released the blob a second time,
and a local user's file with the same bytes lost its content.

## Considered Options

* Delete the row in the transaction that takes its count to zero; a record releases its reference when it is removed or
  when it is erased unremoved, never both
* Keep the zero rows and sweep them later
* Drop the record and its cache entry when it is removed

## Decision Outcome

Chosen option: "delete with the last reference, release once".

* Every writer that takes a count to zero (`commit_local_media_moderation`, `commit_remote_media_admission`) issues
  `DELETE FROM media_blobs` instead of the zero update, in the same transaction, and removes the row from
  `store.media_blobs`. The repository erases its row in memory after the commit, as before.
* A re-upload of deleted bytes inserts a new row through the existing upsert, and writes the bytes. The revival code of
  ADR-0094 is gone with the rows it revived; its one-identity rule still holds, since a row exists only while live.
* A record holds a blob reference exactly while its state is not `removed`. `erase_record_and_release_blob`, and the
  database path in `persist_remote_media_admission`, release only for such a record.
* The loaders skip rows at zero references, so rows written by earlier versions are neither loaded nor counted. They
  stay in the database until the same bytes are uploaded again, which overwrites them. There is no migration: no
  database holds data that needs one before 1.0.

Dropping the removed record instead was rejected: a removed cached record is returned on purpose so the caller refuses
the file without asking the remote server again (`test_media_repository.cpp`, "A cached remote media record is
returned in its moderation state").

## Links

* Supersedes the zero-reference tombstone of [ADR-0094](0094-revive-removed-media-storage-identities.md)
* Related to [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md)
