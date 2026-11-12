# The per-user byte quota is charged for a deduplicated upload

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C42.

## Context and Problem Statement

`capacity_rejection_reason` charged the per-user byte quota only when an upload stored a new blob; an upload that
deduplicated onto bytes already held (anyone's upload, or a cached remote file) skipped it. A user at their quota was
therefore answered 200 for bytes the server already held and 507 for bytes it did not, an oracle for whether a known
file is on the server, repeatable as often as the rate limit allows (ADR-0026 accepted the skip as an accounting
consequence without weighing this).

## Considered Options

* Charge the per-user byte quota for every upload, as `owner_live_bytes` already counts a deduplicated record's size.
* Keep the skip and add a delay or noise to the refusal.
* Count a deduplicated record's bytes in the quota but let the user exceed it for held bytes.

## Decision Outcome

Chosen option: charge every upload. Whether an upload is admitted under a user's quota then depends only on that user's
own records, which is also how `owner_live_bytes` has always counted them, so no accounting changes. Noise was rejected
because it hides a difference rather than removing it, and the third option is the oracle itself.

Not changed: the server-wide byte limit (`max_total_bytes`) still lets an upload of a file the server already holds pass,
because it adds no bytes to a full disk. It is reachable as an oracle only when the whole server is full, which no user
chooses. The smaller timing difference (a deduplicated upload skips the database write of a blob) is also left; it was
not measured, and removing it would mean writing a throwaway blob.

## Links

* Refines [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md)
