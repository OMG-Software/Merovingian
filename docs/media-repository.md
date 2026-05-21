# Media Repository

This capability note describes the local media repository slice through the
current in-process runtime path.

## Runtime Behavior

- Authenticated local uploads run through the homeserver media route.
- `GET /_matrix/media/v3/config` reports `m.upload.size` from
  `security.media.max_upload_size`, so client upload hints match the policy
  enforced by the repository.
- Downloads serve only local media owned by the configured server name.
- Remote media fetches remain disabled and fail closed until a later capability
  change.
- Admin quarantine, release, and remove actions update repository state, persistent metadata, admin actions, and audit events.
- Media metrics expose accepted uploads, rejected uploads, quarantines, releases, removals, remote fetch rejections, stored blobs, and stored bytes.
- The media repository is runtime-wired, but still partial against Matrix
  v1.18 because multipart upload handling, remote fetch, durable blob storage,
  thumbnailing, and sandboxed processing remain production gaps.

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

Schema version `2` adds media metadata columns for `hash_algorithm`, `digest`, and `removed`. Existing version `1` schemas migrate through the `media_metadata_columns` step before startup is considered compatible. New local uploads use LibSodium `crypto_generichash` (`blake2b`) for deduplication digests instead of project-local hash code.

Media moderation events are persisted with the `moderation` audit category so operator filtering can distinguish media policy and admin moderation events from auth or generic admin activity.
