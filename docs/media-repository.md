# Media Repository

This capability note describes the local media repository slice through the
current in-process runtime path.

## Runtime Behavior

- Authenticated local uploads run through the homeserver media route.
- `GET /_matrix/media/v3/config` reports `m.upload.size` from
  `security.media.max_upload_size`, so client upload hints match the policy
  enforced by the repository.
- Downloads serve local media owned by the configured server name.
- Remote media fetches remain disabled by default. The repository now has an
  explicit remote ingest boundary for configured fetchers: remote host/IP policy
  is checked before bytes enter the local blob store, and rejected fetches are
  counted/audited.
- Upload and remote-ingest bytes pass through the same hardened processing
  boundary: AV scanner result, sandboxed worker requirement, decoder safety,
  decompression expansion limits, and thumbnail metadata generation.
- Admin quarantine, release, and remove actions update repository state, persistent metadata, admin actions, and audit events.
- Media metrics expose accepted uploads, rejected uploads, quarantines,
  releases, removals, remote fetch accept/reject counts, processing rejections,
  thumbnail generation, stored blobs, and stored bytes.
- The media repository is runtime-wired, but still partial against Matrix
  v1.18 because multipart upload handling, live remote server discovery/fetch
  transport wiring, and real image resampling remain production gaps.

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
- `502` while remote media fetching is intentionally disabled.

## Deduplication

Local media deduplication uses a LibSodium `crypto_generichash` (`blake2b`) digest and byte size. Removed blobs with a zero reference count are not reused for future uploads, because their bytes have been cleared and reusing them would corrupt successful reuploads.

## Persistence

The collapsed initial schema includes `media` metadata, `remote_media`
metadata, and `media_blobs` durable byte storage. New local uploads use
LibSodium `crypto_generichash` (`blake2b`) for deduplication digests, store the
blob bytes through `media_blobs`, and hydrate the runtime repository from those
rows after a SQLite/PostgreSQL restart.

Media moderation events are persisted with the `moderation` audit category so operator filtering can distinguish media policy and admin moderation events from auth or generic admin activity.
