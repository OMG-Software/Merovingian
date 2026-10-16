# Cache thumbnails in memory and cap concurrent decodes per requester

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding MED-4 (thumbnail generation runs under the
global runtime mutex). Builds on [ADR-0145](0145-bind-local-thumbnail-disclosure-to-source-record-identity.md).

## Context and Problem Statement

Thumbnails were already decoded with `runtime.mutex` released, and a local thumbnail was published only
if its record was still servable afterwards (ADR-0145). Three gaps remained: every request forked the
decoder again, one client could run any number of decodes at once (each up to the thumbnail timeout),
and a remote thumbnail was not revalidated at all after the unlocked decode.

## Considered Options

* **An in-memory LRU of generated thumbnails, a per-requester cap on concurrent decodes, and remote
  thumbnails revalidated against the cached local record their bytes were admitted as (chosen).**
* Persist generated thumbnails in the database. Rejected: a migration, quota accounting and another
  stored copy of user media to moderate, for a cache that rebuilds itself on demand.
* Cap concurrency only, no cache. Rejected: every repeat still forks the decoder.
* Evict cache entries when media is moderated. Rejected: every moderation path would have to remember to
  do it. A hit is served only after the caller has checked the source record is still servable, so a
  quarantined or removed record's thumbnail is withheld without touching the cache.

## Decision Outcome

Chosen option: cache, cap and revalidate.

* `media::ThumbnailCache` lives in `LocalMediaRepository` under `runtime.mutex`. It is keyed by the
  authorising local record (`media_id`, `storage_id`), size and method, bounded by
  `security.media.thumbnail_cache_size` (64 MiB; empty or 0 disables it), least recently used first out.
  Entry cost counts the key, content type and bytes. It stores no iterators, so copying the repository
  is safe.
* `security.media.thumbnail_max_concurrent_per_user` (2) caps decodes in flight per requester: the user
  when the request is authenticated, otherwise the client address. Beyond it the request gets
  `429 M_LIMIT_EXCEEDED` with a one-second retry. The count is an RAII slot held across the unlocked
  decode.
* A remote thumbnail carries the cached local record (`find_cached_remote_media`) into the decode and is
  revalidated like a local one; with the remote cache disabled there is no record and nothing is cached.
  Every thumbnail also asks the media policy again after the decode.

### Negative Consequences

* The cache is lost on restart, and each process start pays one decode per (record, size, method).
* A requester behind a shared address shares one cap with everyone else on it when unauthenticated.
