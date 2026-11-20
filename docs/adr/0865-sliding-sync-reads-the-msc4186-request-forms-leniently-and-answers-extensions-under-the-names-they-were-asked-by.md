# Sliding sync reads the MSC4186 request forms leniently, and answers extensions under the names they were asked by

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4186 (merged 2026-06-29) changed the request and response of simplified sliding sync from the MSC3575 shapes this
server served. Its extensions moved out into MSC4508 (typing and the common scope rules), MSC4538 (to_device), MSC4543
(e2ee), MSC4548 (account_data) and MSC4551 (receipts), each under a prefixed key. Clients in use today (Element X,
matrix-rust-sdk, Persephone) still send the older forms. Several rules of the new text would break those clients or
this server's own tests if read strictly, and several things the text leaves to the server needed a choice.

## Decision Drivers

* A client that works today must keep working: the MSC3575 forms stay accepted beside the MSC4186 ones.
* Every behaviour the MSCs require (MUST) is implemented, or recorded here as a deviation with its reason.
* Work under `runtime.mutex` stays bounded by the request's caps.

## Considered Options

* Implement MSC4186 strictly, refusing the older forms and any list or subscription without `timeline_limit` and
  `required_state`.
* Accept both forms, take defaults for missing fields, and answer each extension under every name the request used.

## Decision Outcome

Chosen option: the second.

* **Forms.** `required_state` is read as the MSC4186 object (`include`, `exclude`, `lazy_members`; `RequiredStateConfig`)
  or the MSC3575 pair list (with `$LAZY`, `$ME`, `*`). In the object form an omitted `type` or `state_key` matches any
  value and `"*"` is a literal, as MSC4186 says; only the pair list reads `*` as any (`RequiredStateElement`). `range` and `ranges` are both read; with neither, the whole
  filtered list is in range. The filters `is_invited` (and the older `is_invite`), `spaces`, `tags`, `not_tags` and a
  `null` entry in `room_types` / `not_room_types` are read. A list key must match the opaque identifier grammar.
* **Missing `timeline_limit` or `required_state` is not refused** (a deviation: MSC4186 marks both required). The list
  or subscription takes the defaults (`timeline_limit` 20 for a list and a subscription; no state). Refusing
  breaks every client that omits one, and about sixty request bodies in the tests. The only request refused as
  malformed is a to_device `limit` that is not a positive integer (400 `M_BAD_JSON`).
* **Caps.** At most 100 lists and 100 room subscriptions (`SlidingSyncLimits`), as MSC4186 says. More is
  400 `M_INVALID_PARAM`.
* **`timeout` without `pos`** is ignored: the request is answered at once ("Ignored when no `pos` is set").
* **Heroes** are sent whenever the room has no name, whatever `include_heroes` says, and are the same users `/v3/sync`
  `m.heroes` names: joined, then invited, then (only when neither has anyone) those who left; at most five, never the
  requesting user. Each hero carries `displayname` and, for older clients, `display_name`.
* **`is_dm`** is sent on every room entry, and a joined room whose DM status differs from the one last sent on the
  connection (a `dm:<room_id>` entry in `rooms_seen` while it was a DM) is sent again even with nothing else new
  ("Must be included in an incremental sync if the DM state changes").
* **Extension names.** `ExtensionNames` records whether the request used the bare key, the prefixed key, or both. A
  request with both is one request, read from the prefixed key. `name_sliding_extensions` answers under each key used.
  `/versions` advertises `org.matrix.msc4508`, `msc4538`, `msc4543`, `msc4548` and `msc4551`, each with `.stable`.
* **account_data** (MSC4548) serves the rooms of its MSC4508 scope (`extension_scope_rooms`), whatever the user's
  membership in them, not only the rooms of the response. A room entering the scope, for the first time or again, is
  sent all of its account data (the MSC allows all on re-entry); the first response with the extension on sends all
  global account data. The connection's `ExtensionScopeHistory` records `account_data_enabled` and
  `account_data_rooms`. Room account data outside the scope does not wake a long poll.
* **e2ee** (MSC4543) sends no `device_lists` in the response to a request without `pos`.
* **receipts** (MSC4551) sends a room entering the scope for the first time its initial receipts: the user's own, and
  every user's on the events of its timeline in this response. A room whose entry is `initial` or
  `expanded_timeline` is sent the receipts on its timeline as well as those that changed.

### Positive Consequences

* Older and newer clients are both served from one endpoint.
* The account_data and receipts extensions send what the MSCs require, no longer bounded by the response's rooms.

### Negative Consequences

* A request MSC4186 calls malformed (no `timeline_limit`) is answered. A client relying on the refusal would not see
  one; none is known.
* `rooms_seen` holds three kinds of prefixed key (`invite:`, `membership:`, `dm:`); `sliding_previously_sent_rooms`
  strips all three, and any new reader of the map must too.

## Links

* Extended by [ADR-0866](0866-a-sliding-sync-pos-is-bound-to-the-user-and-device-it-was-issued-to.md) and
  [ADR-0867](0867-sliding-sync-lists-hold-knocked-left-kicked-and-banned-rooms.md)
* Typing and receipts keep their event wrapper: [ADR-0868](0868-the-typing-and-receipts-extensions-keep-their-event-wrapper.md)
* Builds on [ADR-0861](0861-the-typing-and-receipts-extensions-follow-msc4508-scope-and-wake-a-long-poll-only-within-it.md)
  and [ADR-0863](0863-a-room-entering-the-typing-or-receipts-scope-is-sent-what-it-lacks.md)
