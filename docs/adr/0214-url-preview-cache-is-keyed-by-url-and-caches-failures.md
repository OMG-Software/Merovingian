# The URL preview cache is keyed by URL alone and caches failures

* Status: accepted
* Date: 2026-10-22

## Context and Problem Statement

`preview_url` takes `url` and an optional `ts`: "The preferred point in time to return a
preview for. The server may return a newer version if it does not have the requested version
available." Previews are cached in memory (`media::UrlPreviewCache`, bounded by
`security.media.url_preview_cache_max_entries`, TTL `url_preview_cache_ttl_seconds`). What is
the cache key, and are failures cached?

## Decision Drivers

* Every cache miss is an outbound fetch a client caused (ADR-0213).
* The server keeps no history of past versions, so it can only ever return the newest one.

## Considered Options

* Key by URL and `ts`
* Key by the canonical URL alone; cache failures for a shorter time

## Decision Outcome

Chosen option: "key by the canonical URL alone", because a key that includes `ts` lets a
client force a fresh outbound fetch per request just by changing a number, turning the cache
off and the server into an amplifier. Since this server never has an older version, any cached
preview is "a newer version", which the spec allows; `ts` is validated as an integer and
otherwise ignored. The key is the URL as `http::parse_outbound_url` canonicalises it.

Failures are cached too, for at most 300 seconds (or the TTL if shorter), so a client cannot
make the server retry an unreachable or refused URL on every request. A TTL or entry cap of 0
disables the cache.

### Negative Consequences

* A page that changes is previewed stale for up to the TTL (default one hour).

## Links

* Refines [ADR-0213](0213-url-previews-fetch-through-one-ssrf-gate.md)
