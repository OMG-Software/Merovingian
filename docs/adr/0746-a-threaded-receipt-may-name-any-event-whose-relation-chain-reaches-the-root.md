# A threaded receipt may name any event whose relation chain reaches the thread root

* Status: accepted (amends the admission rule of [ADR-0737](0737-receipts-are-read-through-room-and-user-indexes-and-a-threaded-receipt-must-be-related-to-its-thread.md))
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestThreadedReceipts` failed after the run-3 audit fix C23 (1.0.2).

## Context and Problem Statement

ADR-0737 accepted a receipt filed under a thread root only for the root itself or an event in that thread, found by
`sync::event_thread_id` (an `m.thread` relation, up to three hops). `TestThreadedReceipts` marks a thread read through
an annotation of a reference to the root. The annotation is in the main timeline by the thread rule, so it was refused
with 400.

The spec's 400 condition for `POST /receipt` is "The `event_id` is not related to the `thread_id`", and it does not
define "related". What counts as related, without reopening the cost C23 closed?

## Decision Drivers

* C23: one user must not be able to file receipts under thousands of `thread_id`s of their choice.
* An event's relation chain is one path. Walking it is bounded by the hop limit the thread rule already uses.
* Clients mark threads read through reactions and references to the root, as the Complement test does.

## Considered Options

* Related means the root, an event in its thread, or an event whose `m.relates_to` chain, of any `rel_type`, reaches
  the root within three hops (`sync::event_relates_to`).
* Related means in the thread only (ADR-0737 as written).
* Accept any `thread_id` that is a main-timeline event (the rule before C23).

## Decision Outcome

Chosen option: the first. `receipt_event_is_in_thread` still requires `thread_id` to name a main-timeline event of the
room. It then accepts the event when `event_thread_id` is that root or `event_relates_to` reaches it. Parents are looked
up in the same room only, and a parent this server does not hold ends the chain. Each event has one relation, so an
event is related to at most three roots besides its own thread, and the C23 cap of 256 threaded rows per user and room
is unchanged.

### Positive Consequences

* Reactions to, and references of, a thread root can carry that thread's receipt.

### Negative Consequences

* An event that references a root without being in its thread can move that thread's read marker. That is what the
  client asked for, and it moves only the sender's own marker.

## Pros and Cons of the Options

### In the thread only

* Good, because it is the narrowest reading.
* Bad, because it refuses receipts that clients send and the spec's word "related" allows.

### Any main-timeline `thread_id`

* Bad, because it is the C23 finding: a user chooses freely among every event of the room.

## Links

* Amends [ADR-0737](0737-receipts-are-read-through-room-and-user-indexes-and-a-threaded-receipt-must-be-related-to-its-thread.md)
