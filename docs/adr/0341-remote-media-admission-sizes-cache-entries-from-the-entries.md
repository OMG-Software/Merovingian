# Remote media admission sizes cache entries from the entries and drops a few expired ones

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-47.

## Context and Problem Statement

`plan_remote_media_admission` runs under `runtime.mutex` for every remote file admitted. To count the
cache's bytes it looked up each entry's record with a linear scan of every media record, so one
admission cost about cache entries times records, and the default cache holds 50000 entries. Expired
entries were never dropped, so they held the entry and byte caps.

## Decision Outcome

* `RemoteMediaCacheEntry::size_bytes` is set from the record when an entry is admitted
  (`apply_remote_media_admission`) and restored (`restore_remote_media_cache`), both O(1) through the
  record index. The plan sums the entries' own sizes: one pass over the cache, no record lookups. The
  size is in memory only; hydration recomputes it, so no schema change.
* The plan takes `now_ms` and displaces expired entries, oldest first, **at most 16 per admission**.
  Dropping an entry costs a pass over the records (`erase_record_and_release_blob`), so an unbounded
  drop of a cache that expired together (say 50000 entries after a long idle) would move the
  quadratic cost from planning to applying. The expired entries left over are still held to the caps by
  the least-recently-used eviction, and a later admission drops the next 16.

## Considered Options

* Drop every expired entry at once. Rejected: bounded work under the lock is the point.
* Keep a record-to-size map beside the cache. Rejected: the entry is the one thing that already
  has the lifetime of the cache row.

## Links

* Refines [ADR-0120](0120-cached-remote-media-has-its-own-storage-budget.md)
* Related to [ADR-0121](0121-remote-media-fetches-run-on-their-own-pool.md)
