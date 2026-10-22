# Asynchronous uploads reserve media IDs durably and wait for content on the media fetch pool

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit endpoint gaps (2026-10-17): `POST /_matrix/media/v1/create`
and `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}`

## Context and Problem Statement

`POST /_matrix/media/v1/create` hands out an `mxc://` URI before its content exists. The spec
asks the server to expire unused IDs ("recommended default expiration is 24 hours"), to limit
"the number of concurrent pending media uploads a given user can have" with `429
M_LIMIT_EXCEEDED`, and lets a download of such an ID wait up to `timeout_ms` before answering
`504 M_NOT_YET_UPLOADED`. A reservation is state a client creates; a wait is a request that
holds a thread for as long as the client asks. How are both bounded?

## Decision Drivers

* Every per-user row a request can create must be capped (security audit run-1, ADR-0173).
* No request may hold a main-pool thread or `runtime.mutex` while it waits (ADR-0121).
* A reservation must survive a restart, or a client given a URI cannot complete it.

## Considered Options

* Reservations in memory only; downloads of pending IDs answer 504 at once
* Durable reservations; downloads wait on the request thread with the lock released
* Durable reservations; downloads wait on the media fetch pool, federation answers at once

## Decision Outcome

Chosen option: "durable reservations, waits on the media fetch pool". A reservation is a
`media_pending_uploads` row (migration 026) and an entry in
`LocalMediaRepository::pending_uploads`, created by `plan_pending_media_upload` /
`commit_pending_media_upload`, which also delete the expired reservations they find, in the
same transaction. One user holds at most `security.media.max_pending_uploads_per_user` (default
10) live reservations and the server `max_pending_uploads` (default 10000); both refuse with
`429 M_LIMIT_EXCEEDED`, and both are validated non-zero and bounded. An ID lives
`pending_upload_ttl_seconds` (default 86400). The upload deletes the row in the transaction that
stores the content (`commit_local_media_upload`'s `completes_pending_media_id`), so a restart
sees one or the other. Uploads to a reserved ID go through `media::upload_local_media`, so MIME
policy, quarantine, the size limit and quotas are exactly those of `POST /upload`.

The spec's errors are checked in this order (`admit_pending_media_upload`): content already
stored, `409 M_CANNOT_OVERWRITE_MEDIA` to its uploader (and `403 M_FORBIDDEN` to anyone else,
which is someone else's ID either way); no live reservation, `404 M_NOT_FOUND` (never created,
expired, or another server's name); reserved by someone else, `403 M_FORBIDDEN`. The
client-facing statuses for a refused upload follow the spec for both upload routes: a type the
server does not permit and an exhausted quota are `403 M_FORBIDDEN`, oversize `413 M_TOO_LARGE`.

A client download of a reserved ID without content waits at most
`min(timeout_ms, pending_upload_max_wait_ms)` (spec default 20000; the server cap is 20000,
at most 60000). On a main-pool thread it defers through `RemoteMediaFetchScope`, exactly like a
remote fetch, so the wait runs on the media fetch pool under its admission caps; the wait
itself releases `runtime.mutex` and sleeps on `MediaUploadNotifier`, a leaf condition
variable the upload path signals after its commit. The generation is read before the lock is
released, so an upload in between is not missed. The federation download route has no pool to
defer to and answers `504 M_NOT_YET_UPLOADED` immediately, which the spec allows ("MAY
respond before the timeout"). The legacy v3 download route never waits: media uploaded after
the freeze is never served there (ADR-0068).

A wait holds a worker for its whole length, so it is admitted before it starts
(`await_pending_upload`). At most `media_fetch_threads - 1` waits run at once (none with a single worker), and one requester
may hold half of them (`HomeserverRuntime::pending_upload_waits`): the media fetch pool always
keeps a worker for remote fetches and URL previews, and two client addresses can no longer fill
it with waits. A request served without a media fetch pool waits on its own request thread, so
it also takes an ADR-0079 client-outbound slot, as an inline remote fetch does. A wait that is
not admitted answers `504 M_NOT_YET_UPLOADED` at once, which the spec allows ("The content
repository MAY respond before the timeout"). A full cap is checked before the deferral too, so
a wait that will be refused does not cost a media fetch pool handoff.

### Positive Consequences

* Reservations and waits are bounded by configuration; neither can starve the main pool.
* A reserved URI survives a restart and is completed or expires, never both.

### Negative Consequences

* An expired reservation's row stays until the next `create` sweeps it (bounded by the global
  cap).
* A waiting download occupies a media fetch pool worker for up to the server cap; past
  `media_fetch_threads - 1` concurrent waits, further downloads of reserved IDs get `504` at once
  instead of waiting.

## Pros and Cons of the Options

### In memory only, 504 at once

* Good, because no schema change and no waiting.
* Bad, because a restart loses URIs clients already hold, and ignoring `timeout_ms` entirely
  makes every client that downloads straight after creating see an error.

### Wait on the request thread

* Good, because it is simple.
* Bad, because one client can pin request-pool threads for 20 s each (ADR-0077, ADR-0121).

## Links

* Builds on [ADR-0121](0121-remote-media-fetches-run-on-their-own-pool.md)
* Follows [ADR-0173](0173-cap-global-account-data-types-per-user.md)
