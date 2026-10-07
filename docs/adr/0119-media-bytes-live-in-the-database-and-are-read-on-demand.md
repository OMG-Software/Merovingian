# Media bytes live in the database and are read on demand

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-07

Technical Story: phase 1 of making the database authoritative for reads; follows the
2026-09-29 security audit findings MED-6 and OUT-4.

## Context and Problem Statement

`PersistentStore` hydrated every table into memory at startup and served reads from
those copies; the database was written but not read. For media this meant every stored
file's bytes were held in `LocalMediaRepository::blobs` for the life of the process, so
memory grew with stored media and `security.media.max_total_size` had to be treated as a
memory budget (ADR-0113). Remote media fetched from other servers was held only in
memory and never written to the database. The federation media download path read the
repository without the runtime mutex, while lookups rebuild indices lazily, so it raced
with uploads and moderation.

How should media bytes be stored and served so memory does not grow with stored media?

## Decision Drivers

* Memory use must not grow with the amount of stored media.
* A request must never hold the runtime mutex while reading a large file.
* Moderation must still win: media removed or quarantined while a read is in flight must
  not be served.
* Tests run on an in-memory backend and must keep exercising the same code paths.

## Considered Options

1. Keep bytes in memory; bound them with quotas (the state before this ADR).
2. Read bytes from the database on demand, with the runtime mutex held.
3. Read bytes from the database on demand with the mutex released, re-checking the record
   afterwards.
4. Store media as files on disk outside the database.

## Decision Outcome

Chosen option 3.

* **Memory holds metadata only.** `LocalMediaBlob` has no bytes; hydration does not read
  `media_blobs.bytes`. The record, blob reference counts, digests and the remote-media
  cache map stay in memory; they are small and bounded by `max_records`.
* **Bytes are read per request, outside the mutex.** Under the mutex the caller resolves
  the record and captures a `MediaBlobRead` (the backend location and the storage ID).
  The mutex is released for `read_media_blob`, then re-acquired, and the record is
  checked again: still `available`, same storage ID, blob still referenced. If not, the
  request is refused as if the read had not happened. Option 2 is rejected because a
  50 MiB read under the global mutex stalls every client and federation request.
* **Writes carry bytes straight from the request to the database.** A new blob is
  inserted with its bytes in the same transaction as its media row
  (`commit_local_media_upload`, DB-5); a deduplicated upload updates only the reference
  count.
* **Remote media is persisted like local media**, and its `(origin, media_id)` mapping is
  stored in `remote_media` (migration 020: `local_media_id`, `fetched_at_ms`), so the
  OUT-4 cache survives a restart. Every stored remote copy is reachable from exactly one
  cache entry, or it would never be released:
  * admission is planned, committed and then applied. `plan_remote_media_admission` names
    the entries the new copy displaces (an older entry for the same key, and least
    recently used entries beyond `remote_media_cache_max_entries`);
    `commit_remote_media_admission` deletes their media and cache rows, adjusts blob
    reference counts and inserts the new rows in one transaction; only then does
    `apply_remote_media_admission` change memory;
  * an expired entry is a cache miss but is kept until the re-admission that displaces it,
    so its stored copy is released rather than stranded;
  * an entry is kept whatever moderation does to its record. A quarantined record answers
    451 and a removed one 404 without contacting the origin; quarantined admissions are
    cached too, so the default `quarantine` policy stores one held copy, not one per
    request;
  * `remote_media_cache_max_entries = 0` disables the cache: each admission displaces every
    other entry and is stored already expired, so at most one remote copy is kept and none
    is served from the cache.

  Remote media is a cache: clients only ever hold the origin's `mxc://` URI, so eviction
  breaks no link. Cache times are wall-clock epoch milliseconds, because they are
  persisted.
* **The memory backend is a database.** For `PersistentStoreBackend::memory` the store's
  `media_blobs` rows keep their bytes, because there is no other copy; for SQLite and
  PostgreSQL they hold metadata only.
* **The federation media download takes the runtime mutex for its metadata step**, like
  every other reader, and reads bytes the same way.

Option 4 is rejected for now: it would add a second durable store whose consistency with
the media rows the database transaction currently guarantees.

Removing the in-memory copy made two defects visible, and the decision depends on fixing
them: remote media had never been written to the database, and with an in-memory cache
mapping every restart, TTL expiry, eviction and quarantined request left a stored record
behind, so records would have accumulated until `max_records` refused every upload.

### Positive Consequences

* Process memory no longer depends on stored media; `max_total_size` becomes a storage
  limit rather than a memory budget.
* A slow or large download no longer blocks other requests on the runtime mutex.
* Remote media survives restarts instead of being re-fetched, and its cache is bounded on
  disk as well as in memory.

### Negative Consequences

* Each download costs a database read. SQLite opens a connection per read, as other
  on-demand reads already do; a connection pool is a later phase.
* Between releasing and re-acquiring the mutex a download can read bytes that moderation
  then removes; the re-check refuses them, so the cost is wasted work, not disclosure.

## Links

* [ADR-0113](0113-default-media-quotas-and-single-blob-copy.md) — quotas sized to memory;
  its memory rationale no longer applies once this lands.
* [ADR-0114](0114-cache-remote-media-by-origin-and-media-id.md) — the remote-media cache
  this makes durable.
* [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md) — local media is
  still never evicted.
