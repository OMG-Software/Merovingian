# src/media/ — Media Repository Module

Handles media upload, download, URL preview, and thumbnail generation.
Spec authority: ../../docs/matrix-v1.18-spec/client-server-api.md#content-repository

## Key files

| File | Responsibility |
|---|---|
| `repository.cpp` | Core media store: save, retrieve, deduplicate by content hash |
| `security.cpp` | MIME type allow-list, size limits, quarantine policy |
| `thumbnailer.cpp` | Generates thumbnails for image media |
| `thumbnail_worker_main.cpp` | Out-of-process thumbnail worker entry point (sandboxed) |
| `runtime_media.cpp` | Wires the media service into the runtime |

## Internal body format

The local media router receives requests in pipe-delimited format:

```
declared_mime|sniffed_mime|scanner_clean|<raw binary body>
```

This format is built by `homeserver/client_server.cpp` before calling `call_local()`.
**Never** construct this format outside of `client_server.cpp`.

The 4th field is split on the 3rd `|` — binary bodies containing `|` are safe.

## MIME policy

`security.cpp` enforces:
- `allowed_mime_types` — list from config; defaults to `{"image/png", "image/jpeg", "image/gif", "text/plain", "application/pdf", "application/octet-stream"}`
- `quarantine_unknown_mime = true` — unknown MIME types stored but flagged (status 202 internally); mapped to 200 externally
- `max_upload_size` — from `security.media.max_upload_size` in config (default 100 MiB)

Note: `application/octet-stream` is in the default allow-list because encrypted-room
attachments are uploaded as opaque ciphertext and must not be quarantined. Operators
can override the list with `security.media.allowed_mime_types` if they need a stricter
policy.

## Thumbnail worker

The thumbnail worker runs as a separate sandboxed process (`thumbnail_worker_main.cpp`).
Communication is via pipes. Do not load image decoding libraries in the main server process.

## Key spec section

- [Content Repository](../../docs/matrix-v1.18-spec/client-server-api.md#content-repository)
- `docs/media-repository.md`
