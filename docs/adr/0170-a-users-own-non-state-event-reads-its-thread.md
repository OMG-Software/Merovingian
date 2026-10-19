# A user's own non-state event reads its own thread

* Status: accepted
* Date: 2026-10-19

## Context and Problem Statement

The spec ("Marking notifications as read") says: "When the user updates their read receipt
(either by using the API or by sending an event), notifications prior to and including that
event MUST be marked as read. Which specific events are affected can vary depending on whether a
threaded read receipt was used." Unread counts here were computed from receipts alone, so a user
who replied in a room still had every earlier message from others counted unread until their
client sent a receipt.

The spec does not say whether sending an event works like an unthreaded or a threaded receipt.
It also does not say which events count. This server sends some events in the user's name
without the user looking at the room: a display name or avatar change goes to every joined room
as an `m.room.member` join ("Events on Change of Profile Information").

## Considered Options

* Any event the user sends acts as an unthreaded receipt.
* Any event the user sends acts as a receipt in that event's own thread.
* Only non-state events the user sends act as a receipt in that event's own thread.

## Decision Outcome

Chosen option: only non-state events, each acting as a receipt in its own thread (`main`, or
the root's event ID), because it is the narrowest reading that meets the MUST.

* A message in the main timeline reads the main timeline up to it, and leaves threads alone.
  Posting in the main timeline says nothing about whether the user has read a thread.
* A reply in a thread reads that thread up to it, and leaves the main timeline alone.
* State events never count. Otherwise a profile change, which this server sends to every
  joined room as a state event, would mark every room the user is in as read.

The implicit position counts only for unread counts and `GET /notifications` `read`
(`sync::read_markers_for`). It is not stored as a receipt and is never sent as `m.receipt`. The
spec asks for notifications to be marked read, not for a receipt to be published.

### Positive Consequences

* Replying in a room clears the messages the user was answering.
* Profile changes, joins and other state events sent for the user change no unread count.

### Negative Consequences

* `read_markers_for` scans the user's own events in the room on every count. An event whose
  JSON contains neither `"state_key"` nor `"m.relates_to"` is placed in the main timeline
  without parsing it, which keeps the common case cheap.
* A state event the user really did send by hand (for example a room name change) does not
  mark anything read. The user's client still sends its own receipt.

## Pros and Cons of the Options

### Any event acts as an unthreaded receipt

* Good, because it is the simplest rule.
* Bad, because a main-timeline message would mark every thread read, and a profile change
  would mark every room read.

### Any event acts as a receipt in its own thread

* Good, because thread partitioning is respected.
* Bad, because the server-sent `m.room.member` from a profile change would still mark the main
  timeline of every joined room read.

## Links

* Builds on [ADR-0169](0169-read-receipts-are-durable-and-a-peer-flood-never-evicts-a-local-users-receipt.md)
