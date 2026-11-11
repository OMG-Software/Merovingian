# A claimed one-time key is erased by moving the last row into the gap

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, federation key claim (ADR-0603, ADR-0604)

## Context and Problem Statement

`claim_one_time_key` removed the claimed row with `std::vector::erase`, which shifts every later row. Position indexes
(ADR-0603) hold positions, so a shifting erase would force a rebuild of the index, which is a pass over every one-time key
of every device, and a federated server chooses how often it claims. The same applies to deleting a backup session
(ADR-0606).

## Decision Drivers

* A claim made by a remote server must cost the claimed device's rows, not the table.
* Nothing in the specification orders one-time keys: "the server will choose one", and a fallback key is used only
  when none remain.

## Considered Options

1. Erase in place and rebuild the index after every claim.
2. Erase in place and add the shift to every later position (an O(table) walk).
3. Move the last row into the gap and shrink the vector by one (`erase_row_swap`), patching the index in O(1).
4. Mark the row dead and compact later.

## Decision Outcome

Chosen option 3. `one_time_keys` and `key_backup_sessions` therefore have no meaningful order; nothing reads their
vector position as an order (counts, lookups and the etag, which sorts, do not). Which of a device's keys is claimed
next is the first in that device's list, that is, the oldest still held under the insertion order of the list, which
a swap does not disturb (the list is linked, not positional).

Deleting a device, replacing a fallback key and deleting a backup version erase several rows in one go with
`erase_rows_swap`, highest position first, so the row moved into a gap is never one still to be erased. An index that
was already stale before an erase is rebuilt, not patched.

`devices` and `key_backup_versions` keep their order (the current backup version is the user's last) and are rebuilt
after an erase: a delete of one is a request by its owner and the tables are small per user.

### Negative Consequences

* Code that read the row order of `one_time_keys`, `fallback_keys`, `device_keys` or `key_backup_sessions` as meaningful
  would now be wrong. None does today; a test that pushes rows and expects the first back after an unrelated claim
  would be relying on the order.

### Rejected: mark dead and compact

A tombstone makes every reader skip dead rows and needs a compaction pass under the lock, which is the cost this
decision avoids.
