# A room upgrade keeps `m.federate: false`

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-rooms.room-upgrade.drops-m-federate-false`.

## Context and Problem Statement

`m.federate` is fixed when a room is created and can never change in it. `POST /rooms/{roomId}/upgrade` built the
replacement room's create content from `predecessor`, the old `type` and `additional_creators`, so a member with
tombstone power could turn a local-only room into one remote users may join. The spec leaves the content carried into the
replacement room to the implementation.

## Considered Options

* Copy `m.federate` when it is boolean `false`, and nothing else new.
* Copy every custom property of the old create content.
* Refuse to upgrade a local-only room.

## Decision Outcome

Chosen option: the first. A replacement room is no more federated than the room it replaces. A `true` or absent value is
not copied: it is the default, and a replacement created without the key behaves the same.

Copying every custom property would carry into a new room properties the upgrader does not control and this server does
not understand. Refusing the upgrade would remove a spec feature from every local-only room to avoid a one-key copy.
