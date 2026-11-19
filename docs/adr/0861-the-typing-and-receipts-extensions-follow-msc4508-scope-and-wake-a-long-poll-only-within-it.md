# The typing and receipts extensions follow MSC4508 scope, and wake a long poll only within it

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

[ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)
made the sliding sync `sticky_events` extension read MSC4508's scope keys through `sync::extension_scope_rooms`, and left
the `typing` and `receipts` extensions as they were. Those two read `rooms` alone, in the older way:

* `lists` was ignored, so `{"lists": []}` (subscriptions only) or `{"lists": ["visible"]}` still served every list.
* An absent `rooms`, `[]` and `["*"]` all meant every room in the response: the request struct held a plain vector, so
  "absent" and "empty" could not be told apart.
* A `rooms` naming any other room replaced the whole scope with the rooms named, and reached a joined room the request
  had not subscribed to.
* The long-poll relevance check woke the poll for a receipt or typing change in any room the user had joined, in or out
  of the extension's scope, so an out-of-scope change answered the poll with nothing.

MSC4508 ("Common extension semantics") applies the same scope to every room-scoped extension: a room is in scope when
it is within the range of a list `lists` names, or is a room subscription `rooms` names; an absent key names all, `[]`
none, and `"*"` all. Clients read typing and receipts with the same keys they send for sticky events (matrix-rust-sdk's
room list sends `lists` and `rooms: ["*"]` for both).

## Decision Drivers

* One extension request should mean the same scope for every room-scoped extension.
* A client-named room is not an entitlement (CSAZ-1): only joined rooms are served.
* A long poll must not be answered with nothing; an empty answer is followed by an instant re-poll.
* The scope is decided once, in one place, not copied per extension.

## Considered Options

* Keep the older reading of `rooms` for typing and receipts.
* Read `lists` and `rooms` through `extension_scope_rooms`, as `sticky_events` does, and wake the long poll only for a
  change in the joined rooms of that scope.
* As the second option, but keep waking the poll for any joined room.

## Decision Outcome

Chosen option: the second.

* `ExtReceiptsRequest` and `ExtTypingRequest` hold `std::optional<std::vector<std::string>> lists, rooms`, parsed by the
  same reader as `ExtStickyEventsRequest` (present but not an array of strings is an empty array; each de-duplicated).
  `sliding_sync_request_limit_violation` caps each extension's `rooms` at `room_subscriptions` and its `lists` at
  `lists`, as for `sticky_events`.
* `sync::joined_extension_scope_rooms(lists, rooms, source, room_access)` is the one function every room-scoped
  extension uses: `extension_scope_rooms` over an `ExtensionScopeSource` (the response's list windows and the request's
  subscriptions), less every room `room_access` does not classify as joined. The handler builds the source once per
  response and hands it to `build_extensions` (typing, receipts) and to the sticky extension.
* The long-poll relevance check (`has_relevant_receipts`, `has_relevant_typing`) looks only at the joined rooms of each
  extension's scope over the same windows the sticky check uses (the previous response's, or this request's while a
  list's config is new or changed) and the subscribed rooms. Typing is read per room in scope
  (`room_typing_stream_id_for`), no longer by a walk of every room's typing position.

### Positive Consequences

* `{"lists": [...], "rooms": [...]}` means one scope for typing, receipts and sticky events.
* A connection scoped to its subscriptions, or to a visible-rooms list, is not woken for typing in its other rooms.

### Negative Consequences

* A client that named a joined room in `rooms` without subscribing to it, and relied on that, no longer gets the room's
  typing or receipts unless the room is in a list window in scope. MSC4508 asks for that; it also closes a way to read
  a room's ephemeral data outside what the client asked to sync.
* `"rooms": []` with `lists` absent now leaves the subscriptions out; before, it meant every room in the response.

## Links

* Extends [ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)
* Relates to [ADR-0174](0174-sliding-sync-extension-room-lists-share-the-room-subscriptions-cap.md) (the extension room caps) and
  [ADR-0609](0609-sliding-sync-decides-a-long-poll-wake-from-the-callers-own-rooms.md) (the relevance check)
