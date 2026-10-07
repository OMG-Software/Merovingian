# Cached remote media has its own storage budget

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-07

Technical Story: follows [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md),
which moved media bytes to the database and made the remote media cache durable.

## Context and Problem Statement

Remote media fetched from other servers is stored like local media. Until this decision it
counted toward `security.media.max_total_size` and `max_records`, but the remote media cache
evicted only by entry count. A busy server's cache could therefore fill the local total, and
local users' uploads would fail with `507` because of files nobody on the server uploaded.
How should cached remote media be bounded so it can never take capacity from local uploads?

## Decision Drivers

* Local uploads must not fail because of cached remote media.
* Cached remote media must stay bounded in bytes, not only in file count: one entry can be
  as large as `max_upload_size`.
* Remote media is a cache; evicting it breaks no client link (ADR-0119).

## Considered Options

1. Keep one shared total and document that `remote_media_cache_max_entries` times the
   largest file must fit inside it.
2. Give the remote cache its own byte budget, evict least recently used files to stay within
   it, and stop charging remote media to local quotas.

## Decision Outcome

Chosen option 2, decided by the project owner on 2026-10-07.
`security.media.remote_media_cache_max_size` (default `25GiB`, a tenth of the local total)
bounds cached remote bytes. `plan_remote_media_admission` displaces least recently used
entries until both the entry cap and the byte budget have room for the incoming file; a
single file larger than the whole budget is refused with `507`. Remote media, recognised by
its `@remote-media:<origin>` owner, is excluded from `max_total_size`, `max_records` and the
per-user quota. Option 1 is rejected because the constraint it documents is easy to break and
the failure lands on local users.

A local upload whose bytes are already stored for remote media becomes local usage: it is
charged against `max_total_size` as if it were new, because the bytes now count locally.

### Positive Consequences

* Remote caching cannot cause a local upload to fail.
* Stored remote media is bounded in bytes and in files.

### Negative Consequences

* The two budgets together can use up to `max_total_size + remote_media_cache_max_size` of
  storage; operators size the disk for both.
* A byte shared by a local and a remote record is counted in both budgets. That over-counts
  slightly and never under-counts.

## Links

* [ADR-0119](0119-media-bytes-live-in-the-database-and-are-read-on-demand.md)
* [ADR-0113](0113-default-media-quotas-and-single-blob-copy.md) — the local quota defaults
* [ADR-0114](0114-cache-remote-media-by-origin-and-media-id.md) — the remote media cache
