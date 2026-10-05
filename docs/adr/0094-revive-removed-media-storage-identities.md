# Revive removed media storage identities

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Media storage IDs are derived from content digest and size, and are database
primary keys. Removal retains the metadata row with zero references and empty
bytes. Appending another blob with that same ID on re-upload made lookups and
persistence select the old, empty row (audit MED-3).

## Considered Options

* Restore the existing zero-reference row with the re-uploaded bytes.
* Append another row and make callers choose between duplicate identities.
* Generate a different storage identity for each upload.

## Decision Outcome

Maintain one blob per storage ID. A re-upload restores an emptied row with its
new bytes and initial reference count; it is not counted as deduplication against
live content. Serving lookups require live references. The persistence path
explicitly includes the zero-reference tombstone to erase durable bytes after
final removal. Duplicate identities were rejected because the database cannot
represent them; upload-specific storage IDs would discard content deduplication.

### Positive Consequences

* Re-uploads survive restart and later removal clears their bytes.
* The in-memory identity agrees with the database primary key.

### Negative Consequences

* Persistence must deliberately distinguish tombstone writes from serving lookups.

## Links

* [Media repository](../media-repository.md)
* [Audit MED-3](../security-audit-report-2026-09-29.md#med-3-re-uploading-content-an-admin-removed-corrupts-its-database-row-and-a-later-removal-does-not-erase-it)
