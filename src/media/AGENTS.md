# src/media/ — Media Repository Module

Handles media upload, download, URL preview, and thumbnail generation.
Spec authority: ../../docs/matrix-v1.19-spec/client-server-api.md#content-repository

## Key files

| File | Responsibility |
|---|---|
| `repository.cpp` | Core media store: save, retrieve, deduplicate by content hash |
| `security.cpp` | MIME type allow-list, size limits, quarantine policy |
| `thumbnailer.cpp` | Generates thumbnails for image media |
| `thumbnail_cache.cpp` | `ThumbnailCache`: byte-bounded LRU of generated thumbnails, keyed by source record, size and method (MED-4, ADR-0152). A hit authorises nothing: the caller checks the record is servable first |
| `thumbnail_worker_main.cpp` | Out-of-process thumbnail worker entry point (sandboxed); thin — hardening logic lives in `decoder_hardening.cpp` |
| `decoder_hardening.cpp` | Fail-closed hardening sequence for the thumbnail decoder worker: resource limits + platform sandbox (seccomp/pledge/cap_enter), behind an injectable `DecoderHardeningOps` function table |
| `runtime_media.cpp` | Wires the media service into the runtime |
| `url_preview.cpp` | URL previews' pure parts (ADR-0213): the bounded, non-recursive `og:*`/`<title>` extractor, `resolve_preview_reference` and the bounded `UrlPreviewCache`. No I/O; fetching lives in `homeserver/url_preview_service.cpp` |

## Upload names and reserved IDs

- An upload's `filename` is checked with `media_filename_is_valid` (an invalid one is refused, not
  cleaned) and stored as `LocalMediaRecord::upload_name`; it reaches a header only through
  `media_content_disposition` (ADR-0211).
- `pending_uploads` holds IDs reserved by `POST /_matrix/media/v1/create`; `make_media_id` never
  mints one of them, and `upload_local_media` with `LocalMediaUploadRequest::media_id` fills one
  only once (ADR-0212).

## Internal body format

The local media router receives requests in pipe-delimited format:

```
declared_mime|sniffed_mime|scanner_verdict|<raw binary body>
```

This format is built by `homeserver/client_server.cpp` before calling `call_local()`.
`sniffed_mime` comes from `media::sniff_mime_type()` and `scanner_verdict` (`clean` / `dirty`)
from `media::content_matches_eicar_test_signature()`. There is no real AV engine; the check
recognises the EICAR test file.
**Never** construct this format outside of `client_server.cpp`.

The 4th field is split on the 3rd `|` — binary bodies containing `|` are safe.

## MIME policy

`security.cpp` enforces:
- `allowed_mime_types` — list from config; defaults to `{"image/png", "image/jpeg", "image/gif", "text/plain", "application/pdf", "application/octet-stream"}`
- `quarantine_unknown_mime = true` — unknown MIME types stored but flagged (status 202 internally); mapped to 200 externally
- `max_upload_size` — from `security.media.max_upload_size` in config (default `50MiB`; 100 MiB is
  only the fallback used when the configured value fails to parse)

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

## File names in Content-Disposition (ADR-0211)

A file name (the `{fileName}` of a named download) is client-chosen text that lands in a
response header. Write `Content-Disposition` only with `media::media_content_disposition()`
(`security.cpp`): it leaves out a name that `media_filename_is_valid()` refuses (control
characters, `/`, `\`, invalid UTF-8, over 255 bytes) and encodes the rest per RFC 6266. Never
concatenate a name into a header value anywhere else.

## Thumbnail worker

The thumbnail worker runs as a separate sandboxed process (`thumbnail_worker_main.cpp`).
Communication is via pipes. Do not load image decoding libraries in the main server process.

`main()` calls `media::apply_decoder_hardening()` (`decoder_hardening.hpp`/`.cpp`) before
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

## Key spec section

- [Content Repository](../../docs/matrix-v1.19-spec/client-server-api.md#content-repository)
- `docs/media-repository.md`
