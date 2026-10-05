# Cache remote media by origin server and media ID

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-29

## Context and Problem Statement

Before this change, every request for a remote `mxc://` URI re-fetched the media
from the origin server and re-ran it through the local admission pipeline
(scanner, decoder, quarantine, thumbnailer). This wasted bandwidth and CPU and
allowed a remote server to amplify storage/thumbnail work by returning the same
media ID repeatedly (security audit finding OUT-4). There was no cache, TTL, or
eviction.

## Decision Drivers

* Repeated requests for the same remote URI should serve the already-admitted
  local copy.
* The cache must be bounded so it cannot itself become a denial-of-service
  surface.
* Cached entries must expire so that remote content updates are eventually
  visible.
* Eviction must be predictable (LRU) rather than arbitrary.

## Considered Options

1. **Cache only the raw remote bytes before admission.** Rejected: the
   admission pipeline (scanner, decoder, quarantine) is the expensive part; we
   want to avoid re-running it.
2. **Cache by local media ID only.** Rejected: callers arrive with an
  `(origin_server, media_id)` pair, not a local ID, so the mapping must be keyed
  by the remote pair.
3. **Cache by `(origin_server, media_id)` pointing to the admitted local record,
   with TTL and LRU eviction.** Accepted: it avoids duplicate fetches and
   admission work, is keyed by what the caller provides, and is bounded.

## Decision Outcome

Chosen option: "in-memory vector cache keyed by `(origin_server, media_id)` that
stores the local media ID assigned on first admission, with a configurable TTL
and least-recently-used eviction when the entry cap is reached", because it
saves both network and admission work while keeping memory bounded.

### Positive Consequences

* Repeated remote media requests do not hit the network or re-admit bytes.
* The cache size is capped and old/least-used entries are evicted.
* Cache entries are invalidated when the underlying local record is no longer
  available (quarantined or removed).

### Negative Consequences

* A zero TTL disables caching; a very long TTL delays visibility of updated
  remote media. Defaults are chosen for a one-day window.

## Links

* Security audit finding OUT-4 in `docs/security-audit-report-2026-09-29.md`.
* Related media repository decisions [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md) and [ADR-0068](0068-random-media-ids-and-legacy-endpoint-freeze.md).
