# src/media/ — Media Repository Module

Handles media upload, download, URL preview, and thumbnail generation.
Spec authority: ../../docs/matrix-v1.19-spec/client-server-api.md#content-repository

## Key files

| File | Responsibility |
|---|---|
| `LocalMediaRepository.cpp` | Core media store: save, retrieve, deduplicate by content hash |
| `Security.cpp` | MIME type allow-list, size limits, quarantine policy |
| `Thumbnailer.cpp` | Generates thumbnails for image media |
| `ThumbnailCache.cpp` | `ThumbnailCache`: byte- and count-bounded (`max_thumbnail_cache_entries`) LRU of generated thumbnails, evicted from a recency index (C29, ADR-0690), keyed by source record, size and method (MED-4, ADR-0152). A hit authorises nothing: the caller checks the record is servable first |
| `thumbnail_worker_main.cpp` | Out-of-process thumbnail worker entry point (sandboxed); thin — hardening logic lives in `DecoderHardening.cpp` |
| `DecoderHardening.cpp` | Fail-closed hardening sequence for the thumbnail decoder worker: resource limits + platform sandbox (seccomp/pledge/cap_enter; refuses on NetBSD), behind an injectable `DecoderHardeningOps` function table |
| `ClamdScanner.cpp` | `ClamdScanner` (ADR-0565): clamd `zINSTREAM` over an AF_UNIX socket, one deadline, a bounded number of concurrent scans, fail closed (`ClamdVerdict`: clean / infected / failed / oversize; only clean clears). No logging: `homeserver/ClamdMediaScan.cpp` logs and audits |
| `RuntimeMediaConfig.cpp` | Wires the media service into the runtime |
| `UrlPreview.cpp` | URL previews' pure parts (ADR-0213): the bounded, non-recursive `og:*`/`<title>` extractor, `resolve_preview_reference` and the bounded `UrlPreviewCache`. No I/O; fetching lives in `homeserver/UrlPreviewService.cpp` |

## Upload names and reserved IDs

- An upload's `filename` is checked with `media_filename_is_valid` (an invalid one is refused, not
  cleaned) and stored as `LocalMediaRecord::upload_name`; it reaches a header only through
  `media_content_disposition` (ADR-0211).
- `pending_uploads` holds IDs reserved by `POST /_matrix/media/v1/create`; `make_media_id` never
  mints one of them, and `upload_local_media` with `LocalMediaUploadRequest::media_id` fills one
  only once (ADR-0212). `plan_pending_media_upload` lists at most `max_expired_reservations_swept_per_create` (256)
  expired reservations for deletion; the rest stay until later creates. So every reader of `pending_uploads` must test
  `expires_at_ms` (`find_pending_media_upload` does) and never treat presence as liveness (F-16, ADR-0589). Cost is
  proved with `LocalMediaRepository::pending_rows_examined`, never timing.

## Internal body format

The local media router receives requests in pipe-delimited format:

```
declared_mime|sniffed_mime|scanner_verdict|<raw binary body>
```

This format is built by `homeserver/ClientServerRuntime.cpp` before calling `call_local()`.
`sniffed_mime` comes from `media::sniff_mime_type()` and `scanner_verdict` (`clean` / `dirty`)
from `media::content_matches_eicar_test_signature()`. There is no real AV engine; the check
recognises the EICAR test file; with `security.media.clamd_socket_path` set, `homeserver/MediaService.cpp` also asks clamd (`homeserver::clamd_media_cleared`) after the authenticated user is known and only for `allow-after-scan` media, so the pipe verdict stays the EICAR one.
**Never** construct this format outside of `ClientServerRuntime.cpp`.

The 4th field is split on the 3rd `|` — binary bodies containing `|` are safe.

## MIME policy

`Security.cpp` enforces:
- `allowed_mime_types` — list from config; defaults to `{"image/png", "image/jpeg", "image/gif", "text/plain", "application/pdf", "application/octet-stream"}`
- `quarantine_unknown_mime = true` — unknown MIME types stored but flagged (status 202 internally); mapped to 200 externally
- `max_upload_size` — from `security.media.max_upload_size` in config (default `50MiB`; 100 MiB is
  only the fallback used when the configured value fails to parse)

- Declared vs sniffed: the two match when `media_types_are_equivalent()` says so (case-insensitive,
  and a declared `img/` is `image/`). The allow-list always judges the sniffed type, and a record
  keeps a declared spelling only when it is equivalent to the sniffed type
  (`canonical_content_type` in `LocalMediaRepository.cpp`). Every place that decides by the stored type
  (`content_type_is_inline_safe`, `content_type_is_thumbnailable`, the thumbnail worker's source
  type) must go through `media_types_are_equivalent`, never compare to a literal.

Note: `application/octet-stream` is in the default allow-list because encrypted-room
attachments are uploaded as opaque ciphertext and must not be quarantined. Operators
can override the list with `security.media.allowed_mime_types` if they need a stricter
policy.

## Remote media cache records

Cached remote media is kept out of local quotas (ADR-0120) by `LocalMediaRecord::from_remote_fetch`,
set from the upload request (only the remote fetch sets it) and rebuilt on hydration by
`is_remote_cache_owner(owner, local server name)`. Never classify a record by its owner string
alone: a local account could imitate `@remote-media:` (ADR-0178), and the localpart `remote-media`
is reserved (`auth::localpart_is_reserved`).

## Record share and cache sizes (ADR-0340, ADR-0341)

- `capacity_rejection_reason` charges each owner's live local records against `max_records_per_user` from
  `LocalMediaRepository::owner_record_counts`, for deduplicated uploads too. Anything that adds, erases or
  removes a local record keeps the map in step (`release_owner_slot`, the insert in `upload_local_media`,
  `rebuild_owner_record_counts` on restore). Never count by scanning the records: the check runs under
  `runtime.mutex`.
- The per-user byte quota is charged for a deduplicated upload too (C42, ADR-0689): never pass a "stores a new blob" flag back into
  `capacity_rejection_reason`, or a refusal reveals whether other users hold the bytes.
- `RemoteMediaCacheEntry::size_bytes` is set at admission and hydration. `plan_remote_media_admission` sums
  it and never looks a record up per entry; it drops at most 16 expired entries per admission.

## Counts, indexes and blob rows (ADR-0633, ADR-0636)

- Nothing under `runtime.mutex` may cost time that grows with the records held. The repository keeps, beside the
  vectors, the record, blob and thumbnail position indexes, `local_record_total`, `owner_live_bytes`, `local_holders`
  and `local_held_bytes`, and `live_blob_total`/`live_blob_bytes`. Every writer keeps them in step; `ensure_*` rebuilds
  them once when a vector changed size behind the repository's back. An erase swaps the last row into the gap
  (`records`, `blobs` and `thumbnails` have no order). Prove cost with `LocalMediaRepository::media_rows_examined`,
  never timing.
- A blob row exists only while it has a reference: the last release deletes it (`release_blob_reference`,
  `erase_blob_row`), in the database in the same transaction. A record holds a reference while its state is not
  `removed`; `remove_local_media` releases it, so erasing a removed record releases nothing.

## File names in Content-Disposition (ADR-0211)

A file name (the `{fileName}` of a named download) is client-chosen text that lands in a
response header. Write `Content-Disposition` only with `media::media_content_disposition()`
(`Security.cpp`): it leaves out a name that `media_filename_is_valid()` refuses (control
characters, `/`, `\`, invalid UTF-8, over 255 bytes) and encodes the rest per RFC 6266. Never
concatenate a name into a header value anywhere else.

## Thumbnail worker

The thumbnail worker runs as a separate sandboxed process (`thumbnail_worker_main.cpp`).
Communication is via pipes. Do not load image decoding libraries in the main server process.

`main()` calls `media::apply_decoder_hardening()` (`DecoderHardening.hpp`/`.cpp`) before
reading a single byte of stdin, and the result is fail-closed: if any hardening control
applicable on the current platform fails — a `setrlimit` call, or the platform sandbox
(Linux seccomp decoder profile, OpenBSD `pledge`, FreeBSD `cap_enter`) — the worker writes
the failed control's name to stderr and exits `1` without reading input or touching
libpng/libjpeg-turbo. Never restore the old best-effort behaviour (`std::ignore`-discarded
hardening calls); a sandbox that silently fails to install and then decodes untrusted bytes
unconfined was a real, shipped bug (0.12.13 audit). The real syscalls sit behind
`DecoderHardeningOps`, an injectable function table, so `apply_decoder_hardening()`'s
fail-closed sequencing is unit-testable (`tests/unit/test_media_decoder_hardening.cpp`)
without actually installing a broken sandbox inside the test binary.

A platform with no in-process sandbox (NetBSD) is refused outright: `apply_decoder_hardening()`
returns `no platform decoder sandbox` before it applies anything (ADR-0419). Resource limits alone do
not contain a decoder exploit that can read the server's key and TLS files. Do not "fix" this by
letting NetBSD fall through with rlimits only; add a NetBSD branch to the platform ladder only when
confinement comes from privilege separation. `decoder_platform_sandbox_available()` and
`DecoderHardeningOps::platform_sandbox_available` are the seam; integration tests that expect a
thumbnail call it first and assert the refusal where it is false.

Every request to the worker goes through `exchange_with_worker` in `Thumbnailer.cpp`, including
the library report the server asks for at startup (`query_thumbnail_worker_libraries`, 0.12.45).
Do not spawn the worker any other way: the environment, descriptor sweep, `NO_NEW_PRIVS`, FreeBSD
`fexecve` and deadline live there once. The worker answers the report request, and `--version`,
only after `apply_decoder_hardening()`, and writes them with `write(2)`, never iostreams.

## Key spec section

- [Content Repository](../../docs/matrix-v1.19-spec/client-server-api.md#content-repository)
- `docs/media-repository.md`
