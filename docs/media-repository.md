#Media Repository

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
    but the live fetch path still uses hard - coded discovery / HTTP timeout values.- Upload and remote
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
  whitespace around `=`, a preamble before the first delimiter is skipped,
  LF-only transport padding is tolerated, and the parser fails closed unless
  exactly two parts are present. A `Location` redirect part may carry an empty
  body.

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
  are resampled), or decoding fails, the request returns `404` rather than
  serving the original media bytes, so a thumbnail request cannot be used to
  download arbitrary full-size media.

The worker requires the system `libpng` and `libjpeg-turbo` libraries. When they
are not present at build time the worker is not built and every thumbnail request
returns `404`.

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

## Remote fetches and the runtime lock

Remote download and thumbnail requests arrive through
`handle_local_http_request`, which holds `HomeserverRuntime::mutex` for the
whole request. The federation fetch, its `Location` redirect follow, and the
server-discovery cascade all release that mutex for the network round trip via
`homeserver::NetworkIoUnlock`, and re-acquire it before touching repository
metrics, the audit log, or the blob store.

This matters because the same mutex serialises inbound federation traffic: a
remote that accepted the connection and then went quiet used to freeze every
other client and every inbound `/send` transaction for the fetch's full
120-second budget. See [`http-transport.md`](http-transport.md) "Request lock
and blocking network calls".

## Deduplication

Local media deduplication uses a LibSodium `crypto_generichash` (`blake2b`) digest and byte size. Removed blobs with a zero reference count are not reused for future uploads, because their bytes have been cleared and reusing them would corrupt successful reuploads.

## Persistence

The collapsed initial schema includes `media` metadata, `remote_media`
metadata, and `media_blobs` durable byte storage. New local uploads use
LibSodium `crypto_generichash` (`blake2b`) for deduplication digests, store the
blob bytes through `media_blobs`, and hydrate the runtime repository from those
rows after a SQLite/PostgreSQL restart.

Media moderation events are persisted with the `moderation` audit category so operator filtering can distinguish media policy and admin moderation events from auth or generic admin activity.
