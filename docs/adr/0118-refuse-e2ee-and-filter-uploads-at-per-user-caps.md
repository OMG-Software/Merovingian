# Refuse E2EE key and filter uploads at per-user caps; store filters canonically

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-06

Technical Story: 2026-09-29 security audit finding CSAZ-10.

## Context and Problem Statement

One-time keys, key-signature uploads and filters had no per-user limit, so one
account could grow the store, and the `/keys/query` signature scan run under the
runtime lock, without bound. Each needs a cap. What should happen to an upload
that would cross it, and how is an identical filter recognised without making
every filter upload re-parse every stored filter?

## Decision Drivers

* A cap must bound memory and the work one request can cause.
* Normal clients must never reach it: matrix-rust-sdk keeps about 50 one-time
  keys per device, and clients re-create the same few filters.
* Nothing a client already relies on may silently disappear.

## Considered Options

1. Refuse an upload that would cross a cap, storing nothing from it.
2. Evict the oldest entries to make room.
3. For filters: compare a new filter with each stored one by parsing both.
4. For filters: store new filters in canonical JSON and compare text.

## Decision Outcome

Chosen options 1 and 4, decided by the project owner on 2026-10-06.

An upload that would take a user over `server.client_api.max_one_time_keys_per_device`
(1000), `max_key_signatures_per_user` (10000) or `max_filters_per_user` (1000) is
refused with `400 M_TOO_LARGE` before anything from it is stored. Eviction is
rejected because what it drops is still in use: a filter ID a long-running client
syncs with, or a one-time key the client believes is published.

A filter whose canonical JSON equals one the user already stores returns the
existing `filter_id`, even at the cap. New filters are stored in canonical form so
that comparison is a byte match. Option 3 is rejected because one upload could
then force up to `max_filters_per_user` parses of bodies up to the request size.

Fallback keys are not a decision: the spec requires one per algorithm per device,
and a new one replaces the old.

### Positive Consequences

* Each per-user table is bounded, and a refused request leaves no partial state.
* Re-creating an existing filter neither grows the store nor costs a parse per row.

### Negative Consequences

* The Matrix API has no way to delete a filter, so a user who does reach
  `max_filters_per_user` distinct filters stays there until an operator raises the
  cap. Deduplication makes that unlikely for real clients.
* `GET /user/{userId}/filter/{filterId}` returns the canonical, equivalent JSON,
  not the bytes sent. Filters stored before this change are compared as stored, so
  an old non-canonical filter is not deduplicated against its canonical twin.

## Links

* Security audit finding CSAZ-10 in `docs/security-audit-report-2026-09-29.md`.
* [ADR-0117](0117-bound-to-device-queues-by-recipient-count-and-age.md), the
  to-device half of CSAZ-10.
* [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md), the same
  refuse-not-evict choice for media.
