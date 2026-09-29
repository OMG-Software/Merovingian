# Random media IDs and a per-row legacy-endpoint freeze marker

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-09-22

## Context and Problem Statement

The legacy `/_matrix/media/v3/download` and `/thumbnail` endpoints are
unauthenticated. The pre-0.12.13 media repository minted IDs from a monotonic
counter and a content-digest prefix (`m<seq>_<digest-prefix>`), so an attacker
could enumerate or guess valid media IDs and retrieve arbitrary uploads through
the unauthenticated routes. Matrix v1.19 introduces authenticated
`/_matrix/client/v1/media/...` routes; legacy routes remain required for
backward compatibility, but new uploads must not be reachable through them.

How do we make local media IDs unpredictable while keeping the legacy routes
usable only for pre-upgrade content?

## Decision Drivers

* IDs must be unguessable by anyone who has not been given the MXC URI.
* IDs must be safe to embed in a URL path segment (no `/`, `..`, spaces).
* The same content uploaded twice must still receive different IDs so that
  sharing one MXC URI does not expose the other.
* Legacy unauthenticated endpoints must keep serving old uploads but must fail
  closed for any upload created after the authenticated-media upgrade.
* Authenticated `v1` routes must continue to serve all uploads, old and new.
* The change must not alter the federation-worker table allowlist.

## Considered Options

1. **Keep a counter/digest-derived ID and gate legacy access on a global
   configuration timestamp.** Predictable IDs remain; a configuration value is
   another piece of global state that can be mis-copied or reset during backup
   restoration, silently re-opening old uploads.
2. **Cryptographically random URL-safe IDs with a per-row boolean marker.**
   Each upload gets an independent 128-bit random ID and a `legacy_endpoint_visible`
   flag; new uploads set it `false` so only authenticated routes can retrieve them.

## Decision Outcome

Chosen option: **cryptographically random URL-safe IDs with a per-row boolean
marker**, because it removes predictability entirely and ties the legacy-route
visibility to the persisted row rather than to a global, error-prone config value.

### Positive Consequences

* 16 bytes of CSPRNG output encoded as unpadded URL-safe base64 yields 22
  characters from `[A-Za-z0-9_-]`, the allowed set for Matrix MXC `media_id`
  path segments.
* Collisions are astronomically unlikely; the generator still retries up to a
  fixed bound and rejects the upload if the CSPRNG or encoder fails.
* Deduplication stays byte-for-byte over `media_blobs`; distinct records get
  distinct IDs even when they share the same blob.
* A per-row `legacy_endpoint_visible` boolean means the freeze survives any
  backup/restore or replica promotion that preserves the `media` table.
* The `media` table was already in the federation worker's `worker_never_reads_tables`
  set; adding a column does not change the allowlist.

### Negative Consequences

* Existing pre-upgrade media rows default to `legacy_endpoint_visible = 'true'`
  via the migration, so old unauthenticated links keep working, but operators
  cannot globally disable the legacy endpoints for old content without a separate
  future admin action.
* Media IDs are no longer human-readable counter values; this is intentional.

## Links

* Matrix spec v1.19 Client-Server API § Content repository
* `docs/media-repository.md`
* `docs/database-persistence.md`
* Migration `migrations/016_media_legacy_endpoint_visibility.sql`
