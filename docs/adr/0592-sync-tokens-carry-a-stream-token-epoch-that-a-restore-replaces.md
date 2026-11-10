# Sync tokens carry a stream token epoch that the restore step replaces

* Status: accepted
* Date: 2026-11-10

Technical Story: issue 550, a client offline from a database restore until the sync counter passed its token lost
to-device messages; the gap ADR-0315 left open

## Context and Problem Statement

A `/sync` token's sync component is a position in the server-wide sync stream, and `drain_to_device_messages`
deletes every row for the device at or below it as acknowledged. Restoring a database from a backup sets the counter
back. A client that syncs before the counter reaches its token is served an initial sync (ADR-0315) and is off the old
token. A client that stays offline until the counter has passed its token presents a position the server issues again,
so it cannot be told from a current one: rows numbered after the restore at or below it are deleted undelivered. For
E2EE room keys that is lost history.

ADR-0315 removed `ensure_sync_stream_id_ahead_of`, which let any user raise the server-wide counter with a forged
token (F-03). That path must not come back, and it would not have helped: it acted only on a token presented before
the counter passed it. Telling the late client apart needs something about the token that the restore does not bring
back.

## Considered Options

* A stream token epoch: a random 64-bit value per database, carried in every sync token, replaced by an operator step
  run after a restore
* Raise the counter well past any token at the restore step, by a fixed jump
* Document the restore procedure and leave the gap

## Decision Outcome

Chosen option: "A stream token epoch", because it closes the gap for every client whatever its token, without letting
client input move server-wide state.

* Each database holds one epoch (`stream_token_epoch`, a one-row table). The main process draws a random nonzero one
  at its first start on a database and keeps it across restarts. `merovingian-server --after-restore` replaces it with
  a different random one and exits; operators run it once after restoring a backup and before starting the server.
  It is a mode of the server binary because `merovingian-db-migrate` only plans and never opens the database.
* The epoch is random, not a counter: the same backup can be restored twice, and an incremented epoch would then come
  back the same both times, making the first restore's tokens current again.
* `StreamToken` carries the epoch as an optional fourth hex component, written whenever it is not zero. A token
  without one, or from another epoch, is foreign whatever its positions: `/sync` serves it as an initial sync and
  acknowledges nothing (ADR-0315's answer for a token it cannot serve); sliding sync answers its `pos` 400
  `M_UNKNOWN_POS`.
* The sliding sync `to_device` extension's `since` is its own token, which clients keep across `M_UNKNOWN_POS`. It
  carries the epoch too (`<stream id>_<epoch>`, decimal), and one from another epoch acknowledges nothing. Its old
  reader stopped at the first non-digit; it is now exact.
* `GET /keys/changes` reads a foreign `from` as the start of the log and a foreign `to` as the current position, so a
  client returning after a restore is told every change rather than none.
* Pagination tokens (`/messages`, `/relations`, a timeline's `prev_batch`) are not checked: they name positions to
  read from and nothing is deleted on their account. A restored server gives a stale one a page from the restored
  history.

Raising the counter at the restore step was rejected: any jump is a guess at how far clients got after the backup,
and one too small leaves the gap. Documentation alone was rejected because the loss is silent and the client cannot
recover the keys.

### Positive Consequences

* No token issued before a restore acknowledges a row stored after it, however long the client was offline.
* A forged token still moves nothing: the epoch only makes more tokens foreign.

### Negative Consequences

* Every client gets a full initial sync after a restore, including clients that were current at the backup.
* Tokens issued before this release have no epoch, so every client gets one initial sync after the upgrade, and the
  table is added to the frozen v1 schema in place: a development database must be recreated. There are no users
  before 1.0 ([ADR-0224](0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md)), so neither was shimmed.
* An operator who restores without running `--after-restore` keeps the old gap. The user manual's restore section and
  the operator guide make it a step of the restore.

## Links

* Closes the gap left open by [ADR-0315](0315-a-sync-token-ahead-of-the-streams-is-an-initial-sync-and-the-counter-never-wraps.md)
