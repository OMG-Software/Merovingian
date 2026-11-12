# A receipt EDU commits in one transaction, and the oldest remote rows are evicted from an ordered index

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C36 (the federation receipt sink did a table scan and a database commit per receipt under `runtime.mutex`).

## Context and Problem Statement

The `m.receipt` EDU sink took `runtime.mutex` and, for each accepted receipt (up to 256 per EDU), scanned the whole
receipts vector to see whether the row existed, scanned it again in `store_receipt`, scanned it a third time to find the
oldest remote row once the table held 65536 rows, and committed one database transaction per receipt. A remote server with
a few hundred joined users could send hundreds of such EDUs per second, each priced as one EDU.

## Decision Drivers

* The work under the lock for one EDU must be bounded by the EDU, not by the table.
* An EDU's receipts should be all or nothing: the peer has been told the EDU was accepted.
* A local user's receipts are their unread state; a peer must never evict them.

## Considered Options

* `store_receipts`: plan the whole batch in memory per (user, room) group through the ADR-0737 indexes, commit it (and
  the evictions) as one transaction, and take eviction victims from an ordered set of remote rows.
* A min-heap of remote rows by stream position.
* Charge a receipt EDU by its accepted receipts in the per-origin budget and keep the per-receipt commits.

## Decision Outcome

Chosen option: the first.

* `store_receipts(store, receipts, max_rows)` allocates each row's stream position, applies the threaded-row cap of
  ADR-0737 to the in-memory copy of each touched (user, room) group, and commits every upsert and delete in ONE
  transaction. The mirror changes only after the commit, so a failed commit changes nothing. The sink collects the
  EDU's accepted receipts and calls it once, then queues the appservice receipts.
* `PersistentStore::receipt_remote_by_stream` is an ordered set of `(stream_id, (room, user) group)` for rows of users
  on a server other than `local_server_name`. The oldest remote row is its first entry, so evicting costs O(log n) plus
  the number evicted. It follows the ADR-0603 trust rule (`receipt_remote_indexed_rows`, and the server name it was
  built for), is maintained by the one append and the one erase function of `store.receipts`, and is rebuilt on load
  by `rebuild_key_indexes`. A std::set rather than a map, so two rows with the same stream position (hydrated or
  hand-built rows) both stay.
* Victims in groups the batch touches are skipped, so a batch never deletes a row it just wrote. When no remote row is
  left the table passes its cap rather than a local row being evicted.
* A malformed entry later in an EDU makes the sink reject the EDU before anything is committed; the receipts of
  earlier entries of that EDU are no longer kept (they were before). The EDU was rejected as invalid anyway.

### Negative Consequences

* A heap would be a second structure to keep in step with deletions in the middle; the ordered set erases by key.
* `store_receipt` (one row, optional named eviction) is kept for the client route and tests and shares the code.

## Links

* Builds on ADR-0737 (receipt indexes) and ADR-0603 (row index trust).
