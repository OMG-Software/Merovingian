# Media counts and positions are kept as each record and blob changes, and a row is erased by swapping the last into its place

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.media-repository.record-erase-and-index-rebuild-per-eviction-under-runtime-mutex`

## Context and Problem Statement

Every admission of remote media at the cache cap evicts the least recently used file. The eviction erased the record
from a `std::vector` (moving every later record), rebuilt the whole record index, scanned every blob to refresh the
storage metrics and erased the file's thumbnail with a pass over all thumbnails. Uploads counted the records, the bytes
and the holders of a file by scanning the records. All of it ran under `runtime.mutex`, so one account fetching remote
files could make every request wait for time proportional to the records held. The persistent store's mirror of the
media rows had the same scans (`std::erase_if`, `find_if`, `any_of` over its vectors). How is a media request made to
cost the same however many records exist?

## Decision Drivers

* ADR-0340 and `src/media/AGENTS.md`: the check on an upload runs under `runtime.mutex` and must be O(1).
* About fifty tests and several readers use `repository.records`, `repository.blobs` and `store.local_media` directly.
* A missed writer must cost speed, never a wrong answer (ADR-0344).

## Considered Options

* Keep the vectors; keep a position index and running counts beside them, erase by swapping the last row into the gap
* Mark an erased record as a tombstone and compact later
* Replace the vectors with a slot map or a `std::list`
* Leave the scans and rely on the per-account media rate limit

## Decision Outcome

Chosen option: "positions and counts beside the vectors, erase by swap". It is the shape of `RowKeyIndex` and the other
table indexes (ADR-0344, ADR-0437), and it leaves `records`, `blobs` and `thumbnails` plain vectors that tests read.

* `LocalMediaRepository` keeps, in step with every insert, erase and removal: the record, blob and thumbnail position
  indexes, the number of local records, the bytes each owner holds, the number of local records holding each stored file
  and the bytes of the files held, and the live blob count and bytes. `owner_record_counts_basis` and the blob basis
  (the vector size the counts were built for) detect a vector changed behind the repository's back, and the counts are
  then rebuilt; that is the only scan left, and it costs the records once.
* An erase swaps the last row into the erased row's place and patches that one index entry. The order of `records`,
  `blobs` and `thumbnails` therefore means nothing. Nothing depended on it.
* `PersistentStore` keeps `RowKeyIndex` positions for `local_media`, `media_blobs` and `remote_media`, trusted only
  while their row count equals the vector's, with the same swap-erase.
* The remote media cache is still a vector in recency order. A hit moves its entry to the back and an admission removes
  all displaced entries in one pass, so that is bounded by `remote_media_cache_max_entries`, an operator setting, and
  not by the records held. ADR-0341 already accepted one pass over the cache for planning.
* `LocalMediaRepository::media_rows_examined` and `PersistentStore::media_rows_examined` count rows visited, moved or
  re-indexed, so a test proves the work is bounded without timing.

### Negative Consequences

* The order of the rows is not the order of insertion. A reader that needs an order sorts.
* Every writer of these vectors must keep the counts; the basis check turns a missed one into a rebuild, not into a wrong
  count, unless a row is edited in place without a size change.

## Links

* Refines [ADR-0340](0340-each-user-has-a-share-of-the-local-media-record-cap.md) and
  [ADR-0341](0341-remote-media-admission-sizes-cache-entries-from-the-entries.md)
* Same shape as [ADR-0344](0344-index-current-state-by-room-type-and-key-and-trust-it-only-while-in-step.md)
