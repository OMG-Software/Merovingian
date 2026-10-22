# Media repository

This capability note describes the local media repository slice through the
current in-process runtime path.

## Runtime Behavior

- Authenticated local uploads run through the homeserver media route.
- The declared `Content-Type` header is never trusted as the "sniffed" MIME
  type for policy decisions. `media::sniff_mime_type()` inspects the actual
  upload bytes (magic-byte signatures for PNG/JPEG/GIF/PDF, a printable-ASCII
  heuristic for `text/plain`, falling back to `application/octet-stream`),
  and `evaluate_media_upload()`'s declared-vs-sniffed mismatch check
  quarantines uploads where the two disagree. `client_server.cpp` sniffs the
  client's raw request body for local uploads; `repository.cpp`'s
  `fetch_remote_media` sniffs the raw response body for federated fetches — a
  remote server's declared `Content-Type` is equally untrustworthy. A
  `Content-Type` header containing `|` is rejected with `400 M_BAD_REQUEST`
  rather than spliced into the internal `declared_mime|sniffed_mime|
  scanner_clean|bytes` pipe format, where it could shift field boundaries.
- The `text/plain` sniffing heuristic (issue #445) does not classify content
  that opens with `<` (after leading whitespace) as `text/plain`, even if
  every byte is otherwise printable ASCII — an ASCII-only HTML/JS polyglot
  declared as `Content-Type: text/plain` would otherwise match the sniffed
  type (both `text/plain`) and sail through `evaluate_media_upload`'s
  declared-vs-sniffed mismatch check with no mismatch at all, since
  `text/plain` is in the default MIME allow-list. Such content now sniffs as
  `application/octet-stream`, so a declared `text/plain` upload mismatches
  and is quarantined. `X-Content-Type-Options: nosniff` is set on every
  response regardless (see `docs/http-transport.md`), which independently
  stops a browser from executing it as markup.
- `media_id` validation is unified across every gate (issues #443/#444):
  `security.cpp`'s `media_id_is_valid()` (used for remote-fetch requests) now
  rejects embedded spaces exactly like `repository.cpp`'s stricter
  `media_id_is_safe()` (used at the storage boundary), and the download/
  thumbnail route parser (`local_media_download_parts()` in
  `local_http_router.cpp`) rejects `..` and embedded spaces in the
  `media_id` path segment before it ever reaches the repository layer,
  matching the check the admin media routes already applied.
- `GET /_matrix/media/v3/config` reports `m.upload.size` from
  `security.media.max_upload_size`, so client upload hints match the policy
  enforced by the repository.
- Downloads serve local media owned by the configured server name.
- Federation downloads also use the production `media_policy_decision` before
  repository lookup or blob reads (MED-7, ADR-0144). Persisted exact or
  wildcard media rules and the configured media-surface policy-server hook use
  the same decision path as client downloads. Denial returns 403 without media
  bytes or a media content type; the signed federation dispatcher returns its
  existing JSON error, not `multipart/mixed`. Healthy responses retain the
  two-part federation media format. The provider keeps its runtime lock and
  `RequestLockScope`; hook I/O uses the existing lock-release mechanism, and
  subsequent blob reads retain record/storage revalidation. This is admission
  policy, not a guarantee that a rule changed during hook or blob I/O cancels an
  already admitted request. SQLite/signed-request regression and unavailable-hook
  checks pass 132 assertions in two cases; independent source review passes.
  The fresh normal full suite completes 56 OK with all return codes zero and
  1,026 frozen files unchanged. This is bounded admission acceptance, not
  live policy-server HTTP denial or whole-audit/release acceptance.
- Remote media fetches are opt-in (`security.media.remote_fetch_enabled`, built-in default `false`;
  `config/merovingian.conf.example` sets it to `true`) and
  the flag is checked first: `download_local_media` and `download_local_media_thumbnail` answer
  `404 M_NOT_FOUND` for a remote `serverName` before any policy hook, server discovery or outbound
  call when it is off, and likewise when the request carries `allow_remote=false` (spec: "the server
  should not attempt to fetch the media if it is deemed remote"). This applies to the legacy
  `/_matrix/media/v3/` and the authenticated `/_matrix/client/v1/media/` download and thumbnail
  routes, and so to the federation-media fallback inside `fetch_remote_media_live`. Previously the
  flag was consulted only in `media::fetch_remote_media`, after the bytes had been downloaded
  (audit OUT-7). The refusal is counted (`remote_fetch_rejections`) and audited
  (`media.remote_fetch_rejected`). Accepted remote media is stored in the database under a system
  owner (`@remote-media:<origin>`; the record's `from_remote_fetch` flag, not the owner string, is
  what keeps it out of local quotas, and the localpart `remote-media` cannot be registered,
  ADR-0178), and the cache entry mapping `(origin_server, media_id)` to it is
  stored in `remote_media`, so both survive a restart (ADR-0119). Requests within
  `security.media.remote_media_cache_ttl_seconds` are answered from the stored record without
  contacting the origin: its bytes when available, `451` when quarantined, `404` when removed. A
  re-fetch after the TTL replaces the stored copy, and when `security.media.remote_media_cache_max_entries`
  is reached the least recently used remote copy is deleted, so stored remote media stays bounded.
  `remote_media_cache_max_entries = 0` disables the cache and keeps only the latest fetched copy;
  when fetching is off, downloads of a remote `serverName` answer 404 before any outbound work.
- Media bytes are stored only in `media_blobs.bytes` and read for each download, thumbnail or
  federation media request (ADR-0119). Memory holds records and blob metadata. The read runs with the
  runtime mutex released, and the record is checked again afterwards, so media removed or quarantined
  during the read is not served.
- Generated thumbnails are cached in memory (`security.media.thumbnail_cache_size`,
  64 MiB, least recently used first out; empty or `0` disables it), keyed by the source
  record, size and method, with each axis past the decoder's largest (4096) keyed as
  4096, since the worker clamps it to that; a hit is served only after the record has
  been checked as servable, so moderation needs no cache invalidation. After a decode,
  the media policy is asked first and the record checked last, so a quarantine that
  lands while a policy-server round trip has released the lock is not missed. Each requester (the user, or the client address when
  unauthenticated) runs at most `security.media.thumbnail_max_concurrent_per_user` (2)
  decodes at once; a further request gets `429 M_LIMIT_EXCEEDED`. A remote thumbnail
  carries the cached local record its bytes were admitted as and is revalidated like a
  local one, and every thumbnail re-checks the media policy after the decode (MED-4,
  ADR-0152).
- Local thumbnails also own their source media/storage identity before the blob
  read and revalidate that record after the unlocked decoder returns (MED-4,
  ADR-0145). Availability, matching storage identity and legacy visibility
  must still permit disclosure before a successful PNG is published or counted
  as served. An available alias sharing the same blob does not authorize a
  quarantined or removed record. Refusal is 404 with no decoded PNG or fallback
  original. The existing decoder lock release remains intact. A real SQLite/
  socket/child-gate regression reproduces both moderation races with healthy
  controls; normal GREEN, independent review and fresh full verification are
  pending. This local-only slice does not establish remote-source revalidation,
  generated-output caching, per-user decode admission or strict policy-rule
  revocation during I/O.
- When enabled, a remote fetch runs on the media fetch pool, not the main request pool (ADR-0121;
  `docs/http-transport.md` "Remote media fetch pool"). The refusal, policy and cache checks run first
  on the main pool; only a cache miss is handed to the pool, which admits at most
  `server.http.media_fetch_max_in_flight` fetches (64) and `server.http.media_fetch_max_per_client`
  for one client (8), `429 M_LIMIT_EXCEEDED` with `retry_after_ms` 1000 over either. Concurrent
  requests for the same remote file share one fetch. Every step (discovery, the federation media
  request, the legacy fallback, a `Location` redirect follow) draws from one 30 s deadline (audit
  HTTP-2). Without a media fetch pool (tests, embedded callers) a fetch runs inline under the
  ADR-0079 client-outbound budget: 1 per client address.
- Remote media fetches are live: the homeserver resolves the origin server via
  federation server discovery (`.well-known`, SRV, direct), then tries the
  mandatory authenticated endpoint first per spec (changed in v1.11):
  `GET /_matrix/federation/v1/media/download/
{
    mediaId
}
` (`remote_federation_media_download_url()`),
    signed with an X - Matrix Authorization header the same way outbound transactions are
                           signed.The response is `multipart
                           / mixed` with exactly two parts — an empty JSON metadata part and either the media bytes
        or a `Location` redirect(`parse_federation_media_multipart()`).A `Location` redirect is now followed after SSRF
               - safe resolution and address pinning via
  `resolve_media_redirect_url()` and `federation::resolve_federation_destination()`;
only when the redirect itself cannot be resolved safely does the homeserver fall back.Only on
    a `404` (or an unusable `200`) does the homeserver fall back to the deprecated,
    unauthenticated `GET / _matrix / media / v3 / download / {serverName} /
{
    mediaId
}
` endpoint with `allow_remote =
    false` (`remote_media_download_url()`, percent - encoding both segments so a reserved character in either cannot be
                                                         misread as an extra path segment or
                                               a different route on the resolved host)
        .Calling only the deprecated endpoint — the prior behavior — made every remote fetch 404 against servers that
            disable it by default(current Synapse and Merovingian deployments),
                which is why federated attachments could be sent but never received.Bytes from either path are ingested
                    through the local blob store;
remote host / IP policy is checked before bytes enter the store;
rejected fetches are counted and audited.The private / loopback filter reuses the single source of truth
  `federation::ip_address_is_private_or_loopback` (the `inet_pton`- based numeric path,
                                                       which handles `172.16 /
                                                           12` correctly) rather than a divergent string
    - prefix check,
    so media SSRF blocking and federation SSRF blocking cannot drift apart. `security.media
        .remote_fetch_timeout` is parsed today,
    but the live fetch path uses the fixed 30 s client-outbound deadline instead (ADR-0079).- Upload and remote
        - ingest bytes pass through the same hardened processing boundary : upstream - supplied AV scanner result,
    sandboxed worker requirement, decoder safety, decompression expansion limits,
    and thumbnail metadata generation.Merovingian currently does not launch or configure an AV engine itself; `security.media.enable_av_scanner` only controls whether the policy
  honors the supplied scanner verdict — and, as the "Encrypted media is never
  scannable" section below explains, that verdict can only ever exist for
  plaintext media in unencrypted rooms. Because no real scanner verdict is ever
  produced for federated media, `fetch_remote_media_live()` reports
  `scanner_clean=false` (never a fabricated `true`) for every remote fetch —
  the final disposition is then decided by `MediaAcceptancePolicy` (see
  `security.media.local_upload_policy` / `remote_fetch_media_policy` in
  `docs/user-manual.md`), which defaults remote-fetched media to
  `quarantine` rather than blindly trusting it.
  **Local uploads (issue #418):** `client_server.cpp` previously hardcoded
  `scanner_clean` to the literal `"clean"` in the internal pipe body
  regardless of upload content, making the quarantine-on-infection path
  structurally unreachable even with `enable_av_scanner=true`. It now runs
  `media::content_matches_eicar_test_signature()` — a deterministic,
  dependency-free check for the industry-standard EICAR antivirus test
  string (https://www.eicar.org/download-anti-malware-testfile/) — and
  threads the real result through. This is not a general-purpose AV engine;
  it exists so `enable_av_scanner` has a genuine, testable effect for
  plaintext uploads and the quarantine path can be exercised end-to-end
  without needing real malware.
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
- Federation media downloads use the Matrix v1.11+ authenticated endpoint
  (`GET /_matrix/federation/v1/media/download/{mediaId}`). The `multipart/mixed`
  200 response is parsed strictly per RFC 2046: the boundary delimiter must sit
  on its own line, the boundary token may be quoted or unquoted with optional
  whitespace around `=` and is at most 70 characters (longer is refused), delimiters are found
  with a linear scan because the parse runs under the runtime lock (ADR-0176),
  a preamble before the first delimiter is skipped,
  LF-only transport padding is tolerated, and the parser fails closed unless
  exactly two parts are present. A `Location` redirect part may carry an empty
  body.

## Authenticated media and legacy endpoint freeze (M05)

Remote quarantine is a storage disposition, not download permission. Held
remote content returns 451 with a fixed reason and no payload bytes, and cannot
enter thumbnail processing. Only an admitted 200 result can become a media
response; other internal success statuses are refused with a fixed 502 error.
Held records remain available for moderation and count as rejected remote
fetches rather than accepted deliveries.

Local uploads are assigned 128-bit random, URL-safe media IDs: 16 bytes of
CSPRNG output encoded as 22 unpadded base64url characters (`[A-Za-z0-9_-]`).
The same content uploaded twice receives different IDs because deduplication
happens at the blob level, not the record level. IDs are checked for
uniqueness against the repository before acceptance, and the upload fails
closed if the generator cannot produce a safe ID.

The legacy `/_matrix/media/v3/download` and `/thumbnail` routes are
unauthenticated. To prevent new uploads from being enumerable or retrieved
without a token, every new upload is persisted with
`legacy_endpoint_visible = false`. The legacy routes treat that value as a
404, while authenticated `/_matrix/client/v1/media/download` and
`/thumbnail` routes continue to serve the media. Pre-upgrade rows default to
`legacy_endpoint_visible = 'true'` via migration 016, so existing
unauthenticated links keep working. Hydration restores the persisted visibility
flag on every restart; a record without an explicit flag defaults to private.
See
[ADR-0068](adr/0068-random-media-ids-and-legacy-endpoint-freeze.md).

## Encrypted media is never scannable

**AV scanning cannot inspect the content of media in encrypted rooms, under
any configuration, present or future.** Matrix E2EE attachments are encrypted
client-side (AES-CTR) before upload; the homeserver only ever receives and
stores an opaque ciphertext blob — accepted via the `application/octet-stream`
entry in the default MIME allow-list — and never holds the decryption key,
IV, or hashes needed to read it. Those live only inside the `m.room.encrypted`
event content, itself encrypted end-to-end, which the server also cannot
read. There is no scanner integration, proxy placement, or protocol change
that closes this gap without breaking E2EE's confidentiality guarantee: a
server that could inspect encrypted attachment content could also read
encrypted messages.

Every "scanner verdict" mentioned in this document and in
`security.media.enable_av_scanner` / `local_upload_policy` /
`remote_fetch_media_policy` (`docs/user-manual.md`) therefore applies only
to plaintext media uploaded to unencrypted rooms. For encrypted attachments,
`allow-after-scan` behaves identically to `allow` today, since no scanner —
real or hypothetical — is ever given a verdict to render.

## Thumbnailing

`GET /_matrix/media/v3/thumbnail/{serverName}/{
    mediaId}` and the authenticated
`GET /_matrix/client/v1/media/thumbnail/...` honour the `width`, `height`, and
`method` (`scale` or `crop`) query parameters and return a resampled
`image/png`. Remote thumbnails fetch the media through the same federation
path as downloads (`fetch_remote_media_live`), then resample the fetched bytes
locally through the sandboxed worker; the full-size remote original is never
served in response to a thumbnail request.

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
  the pipe ends to stdin/stdout, and sets `PR_SET_NO_NEW_PRIVS` before `execve()`.
  Exec receives only a fixed `PATH=/usr/bin:/bin`, not the server's environment;
  fd 2 is duplicated onto a pre-opened `/dev/null` sink. The same isolation
  applies to the FreeBSD `fexecve()` path. Sink unavailability fails closed.
- Before reading any input the worker clamps its own address space, CPU time,
  output file size, and descriptor count via `setrlimit`, sets
  `PR_SET_NO_NEW_PRIVS`/`PR_SET_DUMPABLE=0`, and installs the seccomp-bpf filter
  (`platform::apply_decoder_seccomp_filter`).
- The parent (`media::generate_thumbnail`) enforces a wall-clock timeout, an
  input-size limit, an output-size cap, and a pixel-count decode-bomb guard, and
  SIGKILLs a worker that overruns.
- The worker applies the same effective pixel budget to decoded pixels, the
  final thumbnail, and the actual whole-image crop fill (MED-8). Zero still uses
  its 4,096,000-pixel ceiling and a larger request cannot raise it. Rounded crop
  fill axes are checked in 64-bit arithmetic before narrowing or allocation;
  excess area produces the existing empty `too_large` frame. The parent driver
  returns 413 with no media payload, content type, or dimensions; public routes
  retain their existing thumbnail-failure handling. Unexpected C++ exceptions
  use an empty `internal_error` frame prepared after hardening and before input,
  rather than allocating another error string on the failure path. Admitted
  bilinear/center-crop geometry is unchanged. This is not an aggregate memory or
  concurrency budget, nor a broader thumbnail conformance claim. See proposed
  [ADR-0143](adr/0143-bound-thumbnail-crop-intermediates-by-pixel-budget.md).
- A worker's successful response is still untrusted: the parent checks the full
  PNG signature, initial 13-byte IHDR framing, and legal nonzero dimensions
  matching the reported dimensions. A malformed or mismatched PNG returns 502
  without bytes, content type or dimensions. No image decoder or CRC/image-data
  validation runs in the parent. Reported dimensions need not equal requested
  dimensions: an aspect-ratio-preserving scale can legitimately be smaller.
- The worker path defaults to the build-time install location
  (`-DMEROVINGIAN_THUMBNAIL_WORKER_PATH`, mirroring `MEROVINGIAN_SYSCONFDIR`).
  When the worker is missing, the content type is unsupported (only PNG and JPEG
  are resampled), or decoding fails, the request returns `404` rather than
  serving the original media bytes, so a thumbnail request cannot be used to
  download arbitrary full-size media.

The worker requires the system `libpng` and `libjpeg-turbo` libraries. When they
are not present at build time the worker is not built and every thumbnail request
returns `404`.

## Response security headers

Client-facing download and thumbnail responses previously carried only
`Content-Type` and the CORS headers. `apply_media_security_headers()`
(`src/homeserver/client_server.cpp`) now also sets:

- `Content-Security-Policy: sandbox; default-src 'none'; script-src 'none';
  plugin-types application/pdf; style-src 'unsafe-inline'; object-src
  'self';` — the spec's recommended sandboxing policy for the content
  repository.
- `Cross-Origin-Resource-Policy: cross-origin`.
- `Content-Disposition: inline` for the content types in the spec's
  "Serving inline content" allowlist (`text/css`, `text/plain`, `text/csv`,
  `application/json`, `application/ld+json`, `image/jpeg`, `image/gif`,
  `image/png`, `image/apng`, `image/webp`, `image/avif`, `video/mp4`,
  `video/webm`, `video/ogg`, `video/quicktime`, `audio/mp4`, `audio/webm`,
  `audio/aac`, `audio/mpeg`, `audio/ogg`, `audio/wave`, `audio/wav`,
  `audio/x-wav`, `audio/x-pn-wav`, `audio/flac`, `audio/x-flac`), matched
  against the media type only — a trailing `charset` or other parameter
  does not defeat the match, and does not let an unlisted type slip through
  by prefix. `Content-Disposition: attachment` is set for every other
  content type, which is the mitigation the spec names against stored XSS
  through uploaded files.

  The allow-list lives in `media::content_type_is_inline_safe()` and is used
  by both the client-facing download path and the federation multipart body.
  Until 0.12.5 the federation body hardcoded `inline` for every type, so a
  peer's clients were told to render an executable or a scripted document
  inline in the media origin's context — the local allow-list did not apply
  to anything served over federation (audit finding 8). Unknown and
  non-inline-safe types fail closed to `attachment` on both paths.

### Named downloads (R17, 0.12.40)

`GET /_matrix/client/v1/media/download/{serverName}/{mediaId}/{fileName}` and the deprecated
`/_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}` serve the same media as the
two-segment routes (the router accepts one more non-empty segment; thumbnails take none), and
their `Content-Disposition` names the file from the path, as the spec requires ("MUST contain
the file name requested in the path"). The deprecated named route is frozen like the unnamed
one: media uploaded after the freeze is 404 there (ADR-0068).

`media::media_content_disposition()` (`src/media/security.cpp`) writes the header. A name that
`media::media_filename_is_valid()` accepts (at most 255 bytes of well-formed UTF-8, no control
characters, no `/` or `\`) is written as `filename="..."` (with `"` and `\` escaped) when it is
printable ASCII, and as RFC 5987 `filename*=utf-8''<percent-encoded>` otherwise. Any other
name is left out, so no byte a client chose can end or extend the header line (ADR-0211).
Until 0.12.40 the router refused the third segment, so the named routes answered 404 for media
that existed.

### Upload filenames (0.12.40)

An upload's `filename` query parameter (`POST /upload`, `PUT /upload/{serverName}/{mediaId}`) is
stored as `media.upload_name` and returned in `Content-Disposition` on download, as the spec
requires ("If the upload was made with a `filename`, this header MUST contain the same
`filename`"); without one the header carries no filename. An upload whose `filename` fails
`media_filename_is_valid` is refused with `400 M_INVALID_PARAM`, so what is stored is always what
the client sent. A remote server's `Content-Disposition` filename is read by
`media::content_disposition_filename` (quoted, token or RFC 5987 form, at most 1 KiB scanned, an
unsafe name dropped) and stored with the remote copy. Inside the process the stored name crosses
from the local router to the client API in `LocalHttpResponse::media_filename`, a field rather than
a header, so nothing that writes a local-router response to the wire can leak it (ADR-0211).

## Asynchronous uploads

`POST /_matrix/media/v1/create` reserves an `mxc://` URI and returns it with `unused_expires_at`
(now plus `security.media.pending_upload_ttl_seconds`, 24 hours by default). The reservation is a
`media_pending_uploads` row (migration 026) and lives in memory in
`LocalMediaRepository::pending_uploads`. One user may hold `max_pending_uploads_per_user` (10) live
reservations and the server `max_pending_uploads` (10000); past either, `create` answers
`429 M_LIMIT_EXCEEDED`. `create` is also rate limited per user (30 a minute). Expired reservations
are deleted by the next `create`.

`PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` stores the content for a reservation through
the same pipeline as `POST /upload` (MIME sniffing, the scanner check, MIME policy, quarantine,
`max_upload_size`, quotas; pre-body authentication for large bodies), and deletes the reservation
in the same transaction. It answers `200 {}`; `409 M_CANNOT_OVERWRITE_MEDIA` when the ID already
has content; `404 M_NOT_FOUND` for an ID never created, expired, or on another server;
`403 M_FORBIDDEN` when another user created it, when the file type is not permitted, or when a quota
is exhausted; `413 M_TOO_LARGE` when it is too large. `POST /upload` uses the same 403/413 mapping.

A download of a reserved ID whose content has not arrived waits for it, at most
`min(timeout_ms, security.media.pending_upload_max_wait_ms)` (20 s by default and at most 60 s),
then answers `504 M_NOT_YET_UPLOADED`; `timeout_ms=0` answers at once. The wait never runs on a
main-pool thread: it is handed to the media fetch pool like a remote fetch, and it releases the
runtime mutex while it sleeps on `MediaUploadNotifier`, which the upload signals after its commit.
A wait is admitted first: at most `server.http.media_fetch_threads - 1` waits run at once (half of
them for one requester), so the pool always keeps a worker for remote fetches and previews; a
server with no media fetch pool waits on the request thread and then also needs an ADR-0079
client-outbound slot. A wait that is not admitted answers `504 M_NOT_YET_UPLOADED` at once.
The thumbnail routes behave the same way. The federation route
(`GET /_matrix/federation/v1/media/download/{mediaId}`) answers `504 M_NOT_YET_UPLOADED` at once,
and the legacy v3 routes never serve such media (ADR-0068, ADR-0212).

## URL previews

`GET /_matrix/client/v1/media/preview_url` and the deprecated `GET /_matrix/media/v3/preview_url`
are off unless `security.media.url_preview_enabled` is set; while off they answer
`404 M_UNRECOGNIZED`. Both require authentication and are rate limited per user (30 a minute). The
design is ADR-0213; in short:

- `url` must be an absolute `http` or `https` URL of at most 2048 bytes (else `400`); `ts` must be
  an integer and otherwise does not change the answer (ADR-0214).
- Every fetch, the page and every redirect hop and the `og:image`, goes through one gate: the host
  is resolved and refused if any address is private, loopback, link-local, CGNAT, NAT64, multicast,
  reserved or in `security.federation.deny_ip_ranges` (IPv4 and IPv6), and the connection is pinned
  to the checked addresses. Redirects are followed by the gate, at most
  `url_preview_max_redirects` (3). One deadline (`url_preview_timeout_seconds`, 10 s) and byte caps
  (`url_preview_max_page_size` 1 MiB, `url_preview_max_image_size` 5 MiB) bound the whole preview.
- Only HTML is parsed, by a bounded forward scan for `og:*` meta tags and `<title>` that runs
  nothing (`media::extract_open_graph`). Other content previews as `{}`.
- The `og:image` is stored through the upload pipeline as the requesting user's media and
  returned as an `mxc://` URI with `matrix:image:size`; a refused or quarantined image is left out.
- Any failure answers the same `502 M_UNKNOWN`, so the endpoint does not reveal which internal
  names resolve or which addresses answer.
- The work runs on the media fetch pool, never on a main-pool thread, and DNS, every request
  and the HTML parse release the runtime mutex. Results, failures included (for at most 5 minutes), are cached in
  memory by URL (`url_preview_cache_ttl_seconds`, `url_preview_cache_max_entries`), and concurrent
  previews of one URL share one fetch.

## Status Codes

The local HTTP router preserves the media repository status code instead of flattening failures:

- `200` for available uploads, downloads, and successful admin state changes.
- `202` for accepted uploads that are quarantined by policy.
- `400` for malformed media IDs or malformed media route input.
- `401` for unauthenticated upload or admin media requests.
- `404` for missing or removed local media.
- `409` (`M_CANNOT_OVERWRITE_MEDIA`) for an upload to a reserved media ID that already has content.
- `504` (`M_NOT_YET_UPLOADED`) for a reserved media ID whose content has not been uploaded in time.
- `404` for remote media when `security.media.remote_fetch_enabled` is off or the request sets `allow_remote=false`.
- `429` when the client-outbound in-flight budget is exhausted (`M_LIMIT_EXCEEDED`, `retry_after_ms` 1000).
- `413` for uploads that exceed the configured size limit.
- `415` for disallowed MIME types when policy rejects instead of quarantines (the client API answers
  `403 M_FORBIDDEN`, as the spec's upload routes do; likewise `507` for an exhausted quota).
- `451` for quarantined media download attempts.
- `502` when the remote media fetch transport is not available (outbound client or
  discovery network not configured in the runtime).

## Remote fetches and the runtime lock

Remote download and thumbnail requests arrive through
`handle_local_http_request`, which holds `HomeserverRuntime::mutex` for the
whole request. The federation fetch, its `Location` redirect follow, and the
server-discovery cascade all release that mutex for the network round trip via
`homeserver::RuntimeLockRelease`, and re-acquire it before touching repository
metrics, the audit log, or the blob store.

This matters because the same mutex serialises inbound federation traffic: a
remote that accepted the connection and then went quiet used to freeze every
other client and every inbound `/send` transaction for the fetch's full
120-second budget. See [`http-transport.md`](http-transport.md) "Request lock
and blocking network calls".

## Deduplication

Local media deduplication uses a LibSodium `crypto_generichash` (`blake2b`)
digest and byte size. Each storage ID identifies one blob row. Re-uploading
removed content restores that row with the new bytes and one reference;
it does not deduplicate against cleared bytes or append a duplicate storage ID.
Download and thumbnail lookups require a live reference. Persistence also writes
zero-reference tombstones so final removal clears durable bytes.
See [ADR-0094](adr/0094-revive-removed-media-storage-identities.md).

## Persistence

The collapsed initial schema includes `media` metadata, `remote_media`
metadata, and `media_blobs` durable byte storage. Migration 026 adds `media.upload_name` (the
upload's filename) and the `media_pending_uploads` table of reserved media IDs. New local uploads use
LibSodium `crypto_generichash` (`blake2b`) for deduplication digests, store the
blob bytes through `media_blobs`, and hydrate the runtime repository from those
rows after a SQLite/PostgreSQL restart.

Media moderation events are persisted with the `moderation` audit category so operator filtering can distinguish media policy and admin moderation events from auth or generic admin activity.

### Security audit follow-up (0.12.17)

Administrative quarantine, release and removal validate without changing repository state. Metadata, optional blob reference-count/byte clearing, admin_actions and audit_log commit atomically before repository state or metrics change. Any required write failure returns 500 and preserves the prior state across restart (ADR-0100).
