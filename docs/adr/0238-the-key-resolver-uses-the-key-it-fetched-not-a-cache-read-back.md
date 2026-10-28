# The key resolver uses the key it fetched, not a cache read-back

* Status: accepted
* Date: 2026-10-27

Technical Story: Complement run 2 against 0.12.58 failed 35 tests first (and 7 more later) with
`403 remote is unknown` on `send_join`, `invite`, `send_knock` and `/send`.

## Context and Problem Statement

`make_persistent_remote_key_resolver` fetched a remote server's keys, self-verified them, wrote
them to the `server_signing_keys` cache, and then read the requested key back from the store. It
returned only what the read-back found.

A federation worker cannot write that cache. Its SQLite connection is read-only (ISO-4,
`landlock_hardening.cpp`), and its PostgreSQL role has `SELECT` only on `server_signing_keys`
(`provision-federation-worker-role.sql`). A failed write leaves the in-memory mirror untouched
(`store_server_signing_key` updates it only after the commit), so the read-back found nothing and
the resolver returned `std::nullopt`. Every request a worker authenticates from a server whose key
it did not hold at start-up was refused. `make_join` escaped only because the worker skips key
resolution for it, after main has verified the request.

`docs/database-persistence.md` already said the failed write "degrades performance, not
correctness". The code did not do what the document said.

## Decision Drivers

* A worker must verify any server, not only those it knew at start-up.
* The worker's database access stays read-only: widening it is what ISO-4 and the
  least-privilege role exist to prevent.
* A key is trusted for no longer than the cache would trust it: the lesser of `valid_until_ts`
  and seven days after the fetch (rooms/v5.md, ADR-0075).

## Considered Options

* Use the fetched, self-verified key directly; caching is best-effort.
* Keep the read-back, and update the in-memory mirror even when the database write fails.
* Relay key resolution from the worker to main over IPC.
* Give the worker write access to `server_signing_keys`.

## Decision Outcome

Chosen option: use the fetched key directly. The resolver builds the key record from the verified
response, applying the same seven-day cap as `cache_remote_server_keys`, and returns it whether or
not caching succeeded. Discovery must still have succeeded, as before. Within a worker, the
inbound path's `runtime.remotes` keeps the resolved remote, so the next request from that server
does not fetch again.

Do not reintroduce a read-back as "the single source of truth": the cache is an optimisation that
one of the two processes running this code can never fill.

### Positive Consequences

* Workers verify any reachable server, on SQLite and on PostgreSQL with the least-privilege role.
* The worker's database access is unchanged.

### Negative Consequences

* A worker fetches a server's keys once per restart per key, since it cannot persist them.

## Pros and Cons of the Options

### Update the in-memory mirror even when the database write fails

* Bad, because the mirror would then hold rows the database does not, for main as well as the
  worker, and main's other readers assume the two agree.

### Relay key resolution to main over IPC

* Good, because main's cache would serve every worker.
* Bad, because it adds a worker-to-main frame for every unknown key, and main would have to admit
  and bound it like any other worker request (ADR-0071, ADR-0153). A larger change than the bug needs.

### Give the worker write access to `server_signing_keys`

* Bad, because it widens the most exposed process's database rights, which ISO-4 and the
  least-privilege role were introduced to narrow.

## Links

* Relates to [ADR-0075](0075-event-signing-key-validity-is-judged-at-origin-server-ts.md) (key validity cap)
* Relates to [ADR-0153](0153-split-key-resolution-budgets-across-worker-shards.md) (per-shard key-resolution budgets)
* Relates to [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md) (main re-verifies relayed PDUs)
