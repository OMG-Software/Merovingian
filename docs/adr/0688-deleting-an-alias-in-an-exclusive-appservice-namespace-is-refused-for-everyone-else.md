# Deleting an alias in an exclusive appservice namespace is refused for everyone else

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C40.

## Context and Problem Statement

The Application Service API says an exclusive namespace "prevents humans and other application services from
creating/deleting entities in that namespace". `PUT /directory/room/{alias}` and `createRoom` with `room_alias_name`
refuse an alias in another appservice's exclusive namespace with `400 M_EXCLUSIVE`; `DELETE /directory/room/{alias}` did
not, so the alias's creator, a moderator of its room or a server administrator could remove a bridge's reserved alias.

## Considered Options

* Refuse the delete with `400 M_EXCLUSIVE` for everyone but the owning appservice, administrators included.
* Exempt server administrators, who can already act on the alias's room.

## Decision Outcome

Chosen option: no exemption. The creation paths have none (an administrator cannot create a reserved alias either), the
spec names humans and other services without carving out operators, and an operator who needs a reserved alias gone has
the registration to change. The check uses the same `alias_namespace_exclusively_owned_by_other` call and the same
masquerade-token decoding as creation, after the permission check, so a caller with no right to the alias still learns
nothing beyond 403.

`reassign_room_alias` (room upgrade) is unchanged: the spec requires an upgrade to move local aliases, and it is not a
deletion by a human or another service.

## Links

* Related: [ADR-0181](0181-third-party-lookups-take-a-client-outbound-proxy-slot.md) (appservice namespaces on client routes)
