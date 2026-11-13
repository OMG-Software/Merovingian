# A federated join commits its answer in one transaction per part, and writes the auth chain with the runtime lock released

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

`join_room` verifies the resident's send_join answer with `runtime.mutex` released, then takes the lock again and persists
the whole answer: the state array in one transaction, then each auth-chain event in its own transaction, then one
`membership` insert per joined member. The answer is up to `join_response_max_size` (64 MiB) and the resident is chosen by
the joining user's `via`, so a local user running a federating server could make this server do on the order of 10^5
separate commits under the global lock, once per join (run-3 finding C03). A count cap would refuse joins to big rooms, so
the work has to leave the lock, not shrink.

## Considered Options

* One transaction for the auth chain and one for the member rows, and write the auth chain with the lock released (chosen)
* The same, and release the lock for the state-array and member commits too
* A per-user budget on federated joins of large answers

## Decision Outcome

Chosen option: "One transaction for the auth chain and one for the member rows, and write the auth chain with the lock
released".

**Batches.** `prepare_outlier_events_batch` prepares every auth-chain event with `prepare_store_event_with_state`;
`store_memberships_batch` does the member rows. Each is one backend transaction, all or nothing. The commits drop from one
per event and one per member to one each. A member-row failure is logged and the join stands, as the per-row failure was
before (the room's state and the user's own join are already committed).

**Released commit (auth chain only).** `join_room` reserves a stream ordering per auth-chain event under the lock, holds
each in a `PendingStreamOrdering` (ADR-0247: no sync position passes the oldest until its row is in memory), prepares the
batch, then commits it inside a `RuntimeLockRelease{guard}` scope, which releases every recursion level. It retakes the lock
and calls `apply_prepared_outlier_batch`. The commit reads no store state, so nothing else is needed while the lock is
out. The auth-chain events are outliers: `prepare_store_event_with_state` is given no current-state row and no membership
projection, so they write their own event, edge, auth and signature rows only.

What is re-checked at apply, and why the rest cannot change:

* An event the store came to hold in the window is skipped, not applied twice. It can only have been written by a
  transaction that committed first, or this transaction's insert would have failed on the primary key and nothing would be
  applied.
* A failed commit applies nothing and the join answers 500, so memory and the database stay together.
* The room is not held: `PendingJoinLease` is per room (`try_emplace(room_id)`), so an overlapping join of the same room by
  any local user is refused with 429, and `ingest_pdu_event` defers the room's inbound PDUs while the lease is held. The
  lease and the user's `MembershipExchangeClaim` are owned by this frame and are still in place when the lock is retaken.
  The lease covers the whole window: it is taken before the exchange and ends in `take_committed`, after every write here.

**Not released: the state-array commit and the member rows.** Both write `current_state` and `membership` rows. The C41
fix of this audit ([ADR-0696](0696-an-ingest-that-writes-a-current-state-row-commits-under-the-runtime-lock.md),
the commit window in `ingest_pdu_event`) found that committing such rows with the lock out lets a local
send prepare from old memory, commit after, and apply before, leaving memory and the database apart. Releasing for these
two is safe only if nothing else can write those rows for the room during the window. The lease excludes a second join and
inbound PDUs, but not the federation invite handler (which stores state and membership rows for a room this server does not
hold), another local user's knock on the room, or a rejected-invite leave: none of them checks the lease. Making every such
writer check a per-room claim is a change to each of them and is not done here. So those two commits keep the lock, one
transaction each. The auth chain is the bulk of a large answer (the state array holds the room's current state, the chain
holds the history that led to it), and its commit is the one that no longer holds the lock.

Residual: the state-array commit and the member commit of a 64 MiB answer still hold the lock for one transaction each.
Moving them out needs the per-room claim above.

Work that reads no store state is not moved out of the lock either: the auth-chain rows (canonical JSON of each event, its
envelope, its ID) are built from the verified answer under the lock, as `ingest_send_join_state` builds its candidates.
Moving that into `perform_federated_join` changes that function's result type and the filtering that precedes it, and was
left as it is.

Why not a count cap: a big public room's auth chain is legitimately tens of thousands of events. Why not a per-user
budget: it limits how often, not how much per join, and needs state to expire.

## Links

* ADR-0247, ADR-0228, [ADR-0696](0696-an-ingest-that-writes-a-current-state-row-commits-under-the-runtime-lock.md)
