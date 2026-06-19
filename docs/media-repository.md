# Media Repository

This capability note describes the local media repository slice through the
current in-process runtime path.

## Runtime Behavior

- Authenticated local uploads run through the homeserver media route.
- `GET /_matrix/media/v3/config` reports `m.upload.size` from
  `security.media.max_upload_size`, so client upload hints match the policy
  enforced by the repository.
- Downloads serve local media owned by the configured server name.
- Remote media fetches are live: the homeserver resolves the origin server via
  federation server discovery (`.well-known`, SRV, direct), performs an HTTPS
  `GET /_matrix/media/v3/download/{server}/{mediaId}` against the resolved
  host, and ingests the response bytes through the local blob store. Remote
  host/IP policy is checked before bytes enter the store; rejected fetches are
  counted and audited. The private/loopback filter reuses the single source of
  truth `federation::ip_address_is_private_or_loopback` (the `inet_pton`-based
  numeric path, which handles `172.16/12` correctly) rather than a divergent
  string-prefix check, so media SSRF blocking and federation SSRF blocking
  cannot drift apart. `security.media.remote_fetch_timeout` is parsed today,
  but the live fetch path still uses hard-coded discovery/HTTP timeout values.
- Upload and remote-ingest bytes pass through the same hardened processing
  boundary: upstream-supplied AV scanner result, sandboxed worker requirement,
  decoder safety, decompression expansion limits, and thumbnail metadata
  generation. Merovingian currently does not launch or configure an AV engine
  itself; `security.media.enable_av_scanner` only controls whether the policy
  honors the supplied scanner verdict.
- Admin quarantine, release, and remove actions update repository state, persistent metadata, admin actions, and audit events.
- Media metrics expose accepted uploads, rejected uploads, quarantines,
  releases, removals, remote fetch accept/reject counts, processing rejections,
  thumbnail registration (`media_thumbnails_generated_total`), on-demand
  thumbnail resamples (`media_thumbnails_served_total`), stored blobs, and
  stored bytes.
- Thumbnail records mark an ingested image as resamplable; their dimensions stay
  0×0 because no thumbnail is produced at ingest. Thumbnails are generated on
  demand (see below), so a client requesting one always receives a freshly
  resampled image rather than the stored placeholder.
- The media repository is runtime-wired; multipart upload handling remains the
  main outstanding Matrix v1.18 gap.

## Thumbnailing

`GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}` and the authenticated
`GET /_matrix/client/v1/media/thumbnail/...` honour the `width`, `height`, and
`method` (`scale` or `crop`) query parameters and return a resampled
`image/png`.

Untrusted image bytes are **never decoded in the homeserver process**. Decoding
is the highest-risk media operation (libpng/libjpeg parsers are a historic CVE
surface), so it runs in a short-lived, sandboxed child process:

- `merovingian-thumbnail-worker` (installed under `libexecdir/merovingian`)
  reads a single framed request on stdin, decodes PNG (libpng) or JPEG
  (libjpeg-turbo) into RGBA, resamples (bilinear `scale` to fit, or `scale`
  then centre-`crop` to fill), re-encodes PNG, and writes a framed response on
  stdout. It holds no secrets, sockets, or filesystem access beyond the inherited
  stdio pipes. The wire protocol encodes payload lengths as `uint32_t`; both
  `frame_thumbnail_request` and `frame_thumbnail_response` return
  `std::optional<std::string>` and produce `nullopt` when the payload exceeds
  `UINT32_MAX` — callers treat this as a 413 or internal error respectively.
- The parent (`media::generate_thumbnail`) creates its worker pipes with
  `O_CLOEXEC`, closes every non-stdio descriptor in the child after `dup2()`-ing
  the pipe ends to stdin/stdout, and sets `PR_SET_NO_NEW_PRIVS` before `execv()`.
- Before reading any input the worker clamps its own address space, CPU time,
  output file size, and descriptor count via `setrlimit`, sets
  `PR_SET_NO_NEW_PRIVS`/`PR_SET_DUMPABLE=0`, and installs the seccomp-bpf filter
  (`platform::apply_seccomp_filter`).
- The parent (`media::generate_thumbnail`) enforces a wall-clock timeout, an
  input-size limit, an output-size cap, and a pixel-count decode-bomb guard, and
  SIGKILLs a worker that overruns.
- The worker path defaults to the build-time install location
  (`-DMEROVINGIAN_THUMBNAIL_WORKER_PATH`, mirroring `MEROVINGIAN_SYSCONFDIR`).
  When the worker is missing, the content type is unsupported (only PNG and JPEG
  are resampled), or decoding fails, the request **degrades to serving the
  original media bytes** rather than returning an error.

The worker requires the system `libpng` and `libjpeg-turbo` libraries. When they
are not present at build time the worker is not built and every thumbnail request
falls back to the original bytes.

## Status Codes

The local HTTP router preserves the media repository status code instead of flattening failures:

- `200` for available uploads, downloads, and successful admin state changes.
- `202` for accepted uploads that are quarantined by policy.
- `400` for malformed media IDs or malformed media route input.
- `401` for unauthenticated upload or admin media requests.
- `404` for missing or removed local media.
- `413` for uploads that exceed the configured size limit.
- `415` for disallowed MIME types when policy rejects instead of quarantines.
- `451` for quarantined media download attempts.
- `502` when the remote media fetch transport is not available (outbound client or
  discovery network not configured in the runtime).

## Deduplication

Local media deduplication uses a LibSodium `crypto_generichash` (`blake2b`) digest and byte size. Removed blobs with a zero reference count are not reused for future uploads, because their bytes have been cleared and reusing them would corrupt successful reuploads.

## Persistence

The collapsed initial schema includes `media` metadata, `remote_media`
metadata, and `media_blobs` durable byte storage. New local uploads use
LibSodium `crypto_generichash` (`blake2b`) for deduplication digests, store the
blob bytes through `media_blobs`, and hydrate the runtime repository from those
rows after a SQLite/PostgreSQL restart.

Media moderation events are persisted with the `moderation` audit category so operator filtering can distinguish media policy and admin moderation events from auth or generic admin activity.
