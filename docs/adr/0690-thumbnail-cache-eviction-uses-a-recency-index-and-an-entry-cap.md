# Thumbnail cache eviction uses a recency index and an entry cap

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C29.

## Context and Problem Statement

`ThumbnailCache::insert` made room by running `std::ranges::min_element` over the whole cache once per evicted entry,
under `runtime.mutex`. The cache is bounded in bytes, not entries, and a thumbnail's key includes its requested size, so a
client could fill it with hundreds of thousands of tiny entries of one image and then request one large thumbnail, which
evicted tens of thousands of them at the cost of a pass over the cache each.

## Considered Options

* A recency index (`std::map` from the use counter to the key) beside the entry map, so the least recently used entry is the
  first of it, and a cap on the number of entries.
* A `std::list` of keys with iterators held in the map.
* Refuse entries larger than a fraction of the byte budget.

## Decision Outcome

Chosen option: the ordered map, plus a cap of 16,384 entries. The use counter is unique, so it is a valid key, and the cache
stays copyable with no iterators stored (the property its header promises). An insert costs O(log n) per evicted entry, and
with the cap an insert evicts at most 16,384. A list with stored iterators was rejected because copying the cache would
leave the copies pointing into the original. Refusing large entries was rejected because it changes which thumbnails are
cached for an honest large image without bounding the number of small ones.

The cap holds at the default configuration: 64 MiB of typical 2-20 KiB thumbnails is 3,000-30,000 entries, so only a cache of
tiny thumbnails reaches it.

Checked for the same shape: `ResolvedStateMemo` (one eviction per insert), `CachedServerDiscovery`, `GatewayCircuitBreaker`
and `PushRetryQueue` each evict one entry per insert, so none is quadratic; the remote media cache plans its evictions from a
sum it keeps (`plan_remote_media_admission`, ADR-0341).

## Links

* Refines [ADR-0152](0152-cache-thumbnails-in-memory-and-cap-concurrent-decodes-per-requester.md)
