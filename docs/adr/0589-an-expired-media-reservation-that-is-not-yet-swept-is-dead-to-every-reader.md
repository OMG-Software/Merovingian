# An expired media reservation that is not yet swept is dead to every reader

* Status: accepted
* Date: 2026-11-09

Technical Story: Security audit run 4, F-16.

## Context and Problem Statement

`POST /_matrix/media/v1/create` deleted all expired reservations in one request, with a scan of the expired list per row.
Bounding the sweep so a create does bounded work under `runtime.mutex` means some expired reservations survive a create.
What may those leftovers do?

## Considered Options

* Sweep everything, but faster (hash set only): the stall is linear in the backlog, which a population of accounts can
  build once per reservation lifetime.
* Move the sweep to a periodic job.
* Bound the sweep per create (256) and make leftovers harmless.

## Decision Outcome

Chosen option: the third. A create lists at most 256 expired reservations, deletes them with `IN` statements of up to 128 IDs (the prepared-statement parameter limit) and one pass,
and later creates take the rest. A leftover must never behave as a live reservation, so every reader tests `expires_at_ms`:
the quota counts in `plan_pending_media_upload`, `find_pending_media_upload` (and so `admit_pending_media_upload` and the
download waits). Presence in `pending_uploads` is not liveness. `make_media_id` still treats a leftover ID as taken, so it
is never minted twice. A new reader of the reservations tests expiry too.

A periodic job was rejected for now: it needs its own lock discipline and shutdown handling for a low-severity finding,
and creates already visit every reservation once, so they can carry the bounded batch.

### Negative Consequences

* A create still visits every reservation held to count the live ones, so its cost is linear in the backlog; the bound is
  on the rows deleted, not the rows read. Per-owner live counts would remove that and are not done here.
