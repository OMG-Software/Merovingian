# Canonical alias validation checks the aliases an event adds, and only local ones fully

* Status: accepted
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestRoomCanonicalAlias`)

## Context and Problem Statement

`PUT /rooms/{roomId}/state/m.room.canonical_alias` accepted invalid, missing, deleted and
other-room aliases. The spec says servers SHOULD ensure that new aliases are valid and point to
the room (400 `M_INVALID_PARAM` for bad syntax, 400 `M_BAD_ALIAS` for an alias not pointing to
the room), and do not validate aliases being removed or already present.

## Considered Options

* Refuse any remote alias outright.
* Resolve a remote alias over federation before accepting it.
* Check every added alias's syntax; check where it points only when it is this server's.

## Decision Outcome

Chosen option: syntax for every added alias, and the room it points to only for a local alias.

* Only the aliases the content adds are checked (not those already in the room's current
  canonical alias event), as the spec says.
* A remote alias is accepted on its syntax. Checking where it points would be a
  client-triggered federation call; a future change that adds one takes an ADR-0079 slot and
  deadline first. Refusing remote aliases outright would refuse valid content.
* The check runs only for a sender who may send the event, so others still get their 403.
