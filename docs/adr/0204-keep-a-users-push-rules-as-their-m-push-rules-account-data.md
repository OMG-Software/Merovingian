# Keep a user's push rules as their m.push_rules account data, applied over the current defaults

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, finding R19 (push-rule mutation APIs absent; delivery
used read-only defaults)

## Context and Problem Statement

Until 0.12.40 every user had the server-default push ruleset and nothing else. The Push Rules API
(`PUT`/`DELETE /pushrules/global/{kind}/{ruleId}`, `PUT .../enabled`, `PUT .../actions`) lets a
user create, order, delete, enable and re-action rules, and push delivery and unread counts must
follow the result. The rules need durable storage, a way to reach the user's clients, and bounds,
because they are evaluated under `runtime.mutex` for every local recipient of every event and for
every unread event `/sync` counts (R15).

The spec settles two facts: the `m.push_rules` account-data event's content "is the current push
rules for the user" and is sent "in the account_data section of their next /sync request"
("Push Rules: Events"); and servers "MUST reject setting account data for event types that the
server manages by using a 405 error response", `m.push_rules` included, while "Servers must allow
clients to read the above event types as normal" (Client Config, "Server Behaviour").

## Considered Options

* Store the ruleset as the user's global `m.push_rules` account data, and apply it over the
  current server defaults every time it is read
* A dedicated table: reuse the v1 `push_rules` table, or add a new one in a migration
* Store the fully materialised ruleset (defaults included) and treat it as the whole truth

## Decision Outcome

Chosen option: the `m.push_rules` account data, applied over the current defaults.

* `homeserver::load_user_push_rules` builds a `push::UserPushRules` from
  `default_push_ruleset(user)` and the stored content's `global` object. Every edit writes
  `{"global": ruleset()}` back through `set_account_data`, so the change reaches the user's clients
  by the existing account-data sync path with no new stream.
* Only two things are taken from the stored copy of a server-default rule: `enabled` and
  `actions`. A default the stored copy lacks is added with its current definition; a stored default
  the server no longer has is dropped. A server upgrade that changes the defaults therefore
  reaches users who have edited their rules, which a fully materialised copy would freeze.
* Stored user rules are read through the same validator as a `PUT`. A rule that would be refused
  now, and rules beyond the per-user cap, are skipped. The stored copy is therefore not trusted,
  even if it was written before the 405 refusal existed.
* `PUT /user/{userId}/account_data/m.push_rules` (and `m.fully_read`) answers 405 `M_BAD_JSON`, so
  only the Push Rules API writes the row. The server's own write is not subject to the ADR-0173
  type cap: it is one row per user, and the user did not choose it.
* Bounds: `server.client_api.max_push_rules_per_user` (default 200, at most 10000) user-defined
  rules, all kinds together. A new rule past it is refused with `400 M_TOO_LARGE`; an update is
  always allowed. Per rule: an ID of at most 255 bytes, patterns and condition strings of at most
  512 bytes, at most 16 conditions and 16 actions, and at most 4096 bytes of canonical JSON.
  Matching stays linear (ADR-0175). The cap and these bounds make evaluation cost linear in the
  event, with a factor the server chooses, rather than in anything a client stores.
* Rule IDs follow the spec: a leading `.` is refused (reserved for server defaults), as are `/` and
  `\`. A room rule must be named by a room ID (`!`) and a sender rule by a user ID (`@`), because
  the rule ID is what such a rule matches.
* Deleting a server-default rule answers `400 M_INVALID_PARAM`. The spec lists only 200 and 404
  for `DELETE`, and 404 ("The push rule does not exist") would be false for a rule that exists. A
  default rule can be disabled instead.
* Validation is strict on actions: `notify` and `set_tweak` objects are accepted (`highlight` takes
  a boolean value and `sound` a string), `dont_notify` and `coalesce` are stripped as the spec
  requires, and any other action is refused. A condition kind the spec does not define is kept,
  and never matches.

### Positive Consequences

* No migration. Durability, hydration and both database backends come with account data.
* What `GET /pushrules/` serves, what `/sync` carries and what delivery evaluates are one value.

### Negative Consequences

* Evaluation reads the user's account-data row and parses it, once per recipient per event and once
  per `/sync` (R15). The row is bounded by the cap, and no cache is kept.
* The v1 `push_rules` table remains unused.

## Pros and Cons of the Options

### A dedicated table

* Good, because each rule could be one row.
* Bad, because the v1 table's primary key `(user_id, rule_id)` cannot express that a rule ID is
  unique only within its kind, so it needs a migration anyway.
* Bad, because ordering by `before`/`after` needs position bookkeeping across rows.
* Bad, because the `m.push_rules` account-data event would need a second write path to reach
  `/sync`.

### The fully materialised ruleset as the whole truth

* Good, because reading it is a plain parse.
* Bad, because a user who edited one rule would never see a later change to the server defaults.

## Links

* Related to [ADR-0173](0173-cap-global-account-data-types-per-user.md) (account-data type cap)
* Related to [ADR-0175](0175-push-glob-matching-is-linear-and-never-uses-std-regex.md) (linear glob matching)
