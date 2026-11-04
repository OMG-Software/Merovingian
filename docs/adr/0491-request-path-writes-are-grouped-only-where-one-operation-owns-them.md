# Request-path writes are grouped only where one operation owns all of them, and the audit row stays its own commit

* Status: accepted
* Date: 2026-11-04

Technical Story: November analysis P13.

## Context and Problem Statement

`commit_persistent_transaction` is one commit per call, and SQLite runs with `synchronous = FULL` and
`journal_mode = DELETE`, so every commit costs several syncs. The finding said request paths commit once per write.
Counting the transactions of each operation (`PersistentStore::committed_transactions`, with statement capture) showed:

| Operation | Commits before | After |
|---|---|---|
| register | 3 (user, profile, audit) | 2 (user + profile, audit) |
| login | 2 (device + token, audit) | 2 |
| logout | 5 (token, device refresh, device access, device + keys, audit) | 3 |
| state event | 3 | 3 |
| createRoom | 18 | 18 |

Event storage was already one transaction per event with all of its bookkeeping (ADR-0228).

## Decision Outcome

Group the writes that one operation owns and that were separate only by accident:

* `store_user_with_profile`: an account and its empty profile. Registration used to ignore a failed profile write and
  leave an account without one; it now fails and stores nothing.
* `revoke_device_credentials`: the presented access token, the device's refresh tokens and the device's access tokens.
  The checks that follow (`access_token_is_revoked`, `device_tokens_are_revoked`) are unchanged, so ADR-0407's
  "revoke, verify against the store, then mark sessions" order stands.

Durability does not weaken: every response is still sent after its writes committed.

### What is deliberately not grouped

* **The audit row.** It follows the operation as its own commit. Putting it in the operation's transaction would make
  an audit failure fail the operation (today it is logged and ignored), change every call site's failure contract, and
  require a statement-collecting API through code that today commits as it goes. Deferring it to a later commit would let
  a response claim success before its audit row is durable. If this is wanted, it is a decision about the failure
  contract of `append_local_audit`, not a performance tweak.
* **createRoom (18 commits) and other multi-event operations.** Each event is its own transaction because each is judged
  against the state the previous one produced (ADR-0228); one transaction would need the whole chain prepared before
  any of it is applied to memory.
* **Device deletion and its key rows** stay one transaction of their own (`delete_device`), as before.
* **Switching SQLite to `journal_mode = WAL`**, which would halve the syncs of every commit at `synchronous = FULL`, is a
  platform and hardening change (extra files, sandbox paths) and is not made here.

## Consequences

* Do not add a second commit after `store_user_with_profile` or `revoke_device_credentials` for the same operation.
