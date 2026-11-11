# A knock's room state is bounded as an invite's is

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, uncapped, unvalidated answer stored per knock

## Context and Problem Statement

A resident's answer to `send_knock` could be up to the 16 MiB outbound default, every entry of `knock_room_state` cost a
signature check (and a key lookup behind it), and every entry that passed was stored in the knock record, though `/sync`
shows only the summary types and the user's own membership.

## Decision Drivers

* The bounds an invite's `invite_room_state` has (ADR-0619) apply to the same data going the other way.
* Spec (Server-Server API, `PUT /send_knock`): "Entries which are improperly signed or formatted SHOULD be removed". The
  resident has accepted the knock, so a bad list must not undo it.

## Considered Options

* Refuse the whole knock when the list is over a bound
* Keep the first entries up to the bound
* Keep only what `/sync` could show, and drop the whole list when that is over the bound

## Decision Outcome

Chosen option: "Keep only what `/sync` could show, and drop the whole list when that is over the bound".

`bounded_knock_room_state` runs before any signature check. It keeps the seven summary types with an empty state key and
the user's own member event, each at most `events::max_event_size_bytes`. If more than
`federation::max_invite_room_state_entries` (16) remain, or the room's version requires the create event and none is
there, the list is dropped and the knock stands with no state, as it does for an answer with no list. The answer itself is
read up to 1 MiB, the limit on an inbound invite's body; a larger one fails the exchange with a 502 and records nothing.

### Rejected: refusing the knock

The resident already stored it. This server would then disagree with the room about the user's membership.

### Rejected: keeping the first entries

A resident orders the list, so it could push the entries a client needs past the cut, and a partial list looks complete.

### Negative Consequences

* A resident that sends more than 16 summary entries gets a knock with no preview.
