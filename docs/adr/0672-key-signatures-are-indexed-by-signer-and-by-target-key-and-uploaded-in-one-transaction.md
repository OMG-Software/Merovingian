# Key signatures are indexed by signer and by target key, and an upload is one transaction

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C14, `store_key_signature` searching the whole `key_signatures` vector once per uploaded signature

## Context and Problem Statement

`POST /keys/signatures/upload` stored each signature with `store_key_signature`: one committed statement, then a linear search of
the server-wide `key_signatures` vector for the (signer, target user, target key) row. The cap check scanned the whole table for
the signer's rows, and publishing a key (`merge_visible_key_signatures`) walked every signature that targets the user once per
key the user publishes. All of it ran under `runtime.mutex`, and a signer at the cap could repeat 10,000 replacements for free. How
is the work bounded by the request and by the rows it concerns?

## Considered Options

* Three position indexes beside the vector, and one transaction per upload
* The same indexes, but still one commit per signature
* A per-request signature cap below 10,000

## Decision Outcome

Chosen option: "Three position indexes beside the vector, and one transaction per upload".

`PersistentStore` holds `key_signature_key_index` (a `RowKeyIndex` by signer, target user and target key),
`key_signature_signer_index` and `key_signature_target_key_index` (`RowGroupIndex`es), next to the existing target-user index. They
follow ADR-0603: used only while built for exactly the vector's row count; `store_key_signatures` rebuilds a stale set before it
relies on it, and `rebuild_key_signature_index` (hydration, direct fills) rebuilds all four. Signature rows are never erased, so each
write is an append or an in-place update and no index needs an erase path. `store_key_signatures` commits all rows of an upload in
one transaction; a refused row (empty key or payload) is skipped and the call returns false, as the per-row loop did. The cap check
reads the signer's rows through `for_each_signer_key_signature` and the merge reads one key's rows through
`key_signatures_for_target_key`; both count into `key_rows_examined`.

### Rejected: indexes with one commit per signature

The audit measured about 21 s per 10,000-signature request on SQLite, mostly from the per-signature commits; the indexes alone
leave that.

### Rejected: a lower per-request signature cap

It would change what a legitimate cross-signing upload may carry and still leave a commit per signature. The per-user cap
(`max_key_signatures_per_user`) is unchanged.

### Negative Consequences

* A signer at its cap that re-uploads all of its rows still reads those rows once for the cap check, up to the cap, once per request.
