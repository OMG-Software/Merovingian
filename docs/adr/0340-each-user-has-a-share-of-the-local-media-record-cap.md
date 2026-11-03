# Each user has a share of the local media record cap

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-46.

## Context and Problem Statement

`security.media.max_records` bounds the memory the media records use, and it was one budget for the
whole server. The per-user byte quota did not help: distinct one-byte files cost a user one byte each,
and a deduplicated upload is charged no bytes at all. One account uploading for long enough used
the whole cap, after which every user's upload was refused until an operator raised the limit.
Records are never erased for a local user, so the condition outlived a restart.

## Decision Drivers

* A shared budget needs a per-principal share, as the byte quota and the pending-upload
  reservations already have.
* The check runs under `runtime.mutex` on every upload, so it must be O(1).
* The server-wide cap is a memory bound and must keep holding.

## Considered Options

* A per-owner count of live local records, `security.media.max_records_per_user`, checked in
  `capacity_rejection_reason` for every local upload, kept as a map updated at insert, erase, removal
  and hydration.
* A rate limit on uploads per account.
* Charging a minimum number of bytes per record against the byte quota.

## Decision Outcome

Chosen option: the per-owner record count, default 20000 (a fiftieth of the default cap, so fifty
accounts can fill the server and one cannot), `0` for no limit.

* A deduplicated upload is charged a record like any other: it adds a record and no bytes.
* Cached remote media (`from_remote_fetch`) is never counted, so it cannot use anyone's share, and a
  local account named like the remote-cache owner is counted for its own local records only
  (ADR-0178).
* An admin-removed record frees its owner's slot, since the owner no longer holds content. It still
  counts against the server-wide cap, because the record stays in memory; so removal cannot be used
  to hold more records than `max_records` in memory.
* The map is rebuilt on hydration, and `LocalMediaRepository::owner_record_counts_basis` makes a record
  list that changed behind the repository's back rebuild it rather than serve a stale count.

### Positive Consequences

* One account cannot refuse every other account's uploads.

### Negative Consequences

* A user with a very large media history reaches 20000 records; the operator raises the key.
* Another place that adds or erases a local record must keep the map in step; the basis check
  catches a missed one only when the list's size changed.

## Links

* Related to [ADR-0026](0026-refuse-media-uploads-at-capacity-rather-than-evicting.md)
* Related to [ADR-0113](0113-default-media-quotas-and-single-blob-copy.md)
