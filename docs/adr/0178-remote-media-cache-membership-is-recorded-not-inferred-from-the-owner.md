# Remote media cache membership is recorded on the record, not inferred from the owner string

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `med01.remote-media-owner-sentinel-localpart-collision`

## Context and Problem Statement

ADR-0120 keeps cached remote media out of local quotas: it is stored under the owner
`@remote-media:<origin>` and charged to the remote cache's budget. Whether a record was remote was
decided by that owner prefix. Any local user could register the localpart `remote-media`; their own
user ID, `@remote-media:<this server>`, has the same prefix, so their uploads escaped
`max_total_size` and `max_records`.

## Decision Drivers

* Quota accounting must not depend on a name a user can choose.
* No schema change if one is avoidable.
* Accounts that already hold the name, created before this change, must not keep the bypass.

## Considered Options

* Record `from_remote_fetch` on each media record; rebuild it on hydration from the owner and the
  local server name; and reserve the localpart
* Reserve the localpart only
* Add a persisted `from_remote_fetch` column (a migration)

## Decision Outcome

Chosen option: "record the flag, rebuild it on hydration, and reserve the localpart".
`LocalMediaRecord::from_remote_fetch` is set from the upload request, which only the remote fetch
sets, and quota accounting reads it. On hydration, `media::is_remote_cache_owner` sets it when the
persisted owner has the prefix and its server name is not this server's. A local account's user ID
always carries this server's name, and this server never caches media fetched from itself, so the
rule cannot match a local account, including one created before this change.

`auth::localpart_is_reserved` refuses the localpart `remote-media` at every account-creation path
(`/register`, appservice registration and `make_user`). `/register/available` answers it as taken
(`400 M_USER_IN_USE`).

### Positive Consequences

* No migration, and the classification holds for existing data.
* Nobody can register the name from now on.

### Negative Consequences

* An account already called `remote-media` keeps its name; its media is simply charged normally.

## Pros and Cons of the Options

### Reserve the localpart only

* Bad, because an account created before the change keeps the bypass.

### A persisted column

* Good, because the flag would be stored rather than rebuilt.
* Bad, because it needs a migration and backfill for no gain over the owner-and-domain rule.

## Links

* Refines [ADR-0120](0120-cached-remote-media-has-its-own-storage-budget.md)
