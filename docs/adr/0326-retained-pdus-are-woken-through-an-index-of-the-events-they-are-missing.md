# Retained PDUs are woken through an in-memory index of the events they are missing

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-18 (`wake_deferred_pdus_waiting_for` searched up to 6.4 MiB of attacker-chosen
JSON under `runtime.mutex` for every PDU stored in a room)

## Context and Problem Statement

A federation PDU this server cannot yet place is retained (ADR-0165) and retried when the history it needs arrives.
After every PDU stored in a room, `wake_deferred_pdus_waiting_for` made the room's retained PDUs due that "name" the
stored event. It did so by `std::string::find` of the event ID in each retained row's JSON, with the global mutex held.
A remote server chooses those rows (100 per room, about 64 KiB each) and can fill them with `$`, so each stored PDU of
the room cost millions of comparison steps. The same text search also woke a PDU that merely carried the ID in its
content. Retry phase 1 copied the whole table (up to 16 MiB) by value under the mutex every cycle.

How does a stored event find the retained PDUs that were waiting for it without reading them?

## Considered Options

1. A `deferred_pdu_awaits` table, written with the row.
2. An in-memory map from each awaited event ID to the retained PDUs missing it, derived from the rows and rebuilt after
   hydration.
3. Keep the search and cap the JSON scanned.

## Decision Outcome

Chosen option: 2. `PersistentStore::deferred_pdu_awaits` maps an awaited event ID to the retained rows (and their rooms)
missing it. `upsert_deferred_pdu` and `remove_deferred_pdu` keep it in step with `deferred_pdus`;
`rebuild_deferred_pdu_awaits` derives it after hydration by parsing each row's `prev_events` and `auth_events` once;
`take_deferred_pdus_awaiting(store, room, event)` is the lookup and also the wake: it returns the rows of that room that
awaited the event and stops indexing them under it. A caller that pushed rows without the helpers leaves the row count
unequal to `indexed_rows`, and the lookup rebuilds first, so a missed writer costs one rebuild and never a missed wake.

A PDU is indexed under the IDs it is missing, defined once as `database::find_missing_event_references` (an
`auth_events` ID with no stored event; a `prev_events` ID that is not stored or has no recorded state group), which
`collect_missing_pdu_references`, the check that decides to backfill, now calls. A PDU retained although it is missing
nothing (its state before it could not be resolved) is indexed under everything it references. An update of a retained
row (a retry that failed again) re-derives its IDs.

Option 1 was rejected: the schema is frozen (ADR-0224), and the index is a function of the rows, the events and the state
groups, so a second durable copy could only disagree with them. Option 3 was rejected: it bounds the cost without
removing it, and keeps waking rows that merely mention an ID. Retry phase 1 reads the rows in place and applies drops
and removals after the pass, copying only the rows it retries (at most 32).

### Negative Consequences

* A retained PDU that is missing an event stored by a path that does not call `wake_deferred_pdus_waiting_for` still waits
  out its back-off, as it did.
* Indexing parses a retained row's JSON once per insert and once per update, under the lock; the row is bounded
  (about 64 KiB).
