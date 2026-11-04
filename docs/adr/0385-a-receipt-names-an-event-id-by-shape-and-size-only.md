# A receipt names an event ID by shape and size only

* Status: accepted
* Date: 2026-11-03

Technical Story: a receipt or read marker accepted any non-empty string as its event ID, up to the 1 MiB
request body cap, and kept it, showed it to every member of the room and sent it to every server in it.

## Context and Problem Statement

`POST /rooms/{roomId}/receipt/{receiptType}/{eventId}` types `eventId` as an Event ID, and the appendices
cap an event ID at 255 bytes. Which checks does a receipt's event ID get, in the client handlers, in the
inbound `m.receipt` EDU sink and in the store?

## Considered Options

* `events::event_id_is_valid` plus a 255-byte cap
* `events::event_id_is_acceptable_in_receipt`: the same, and also the `+` and `/` of a version 3 event ID
* The same checks, and also require that the event is stored in the room

## Decision Outcome

Chosen option: `event_id_is_acceptable_in_receipt`, a shape and size check only.

**`event_id_is_valid` is the room version 4 grammar.** An event ID in a version 3 room is the unpadded
standard base64 of the reference hash, which holds `+` and `/`, and the room version table still lists
version 3 as supported. Using `event_id_is_valid` alone would answer 400 to every read receipt a client
sends in such a room. A later reader who sees two functions that look alike must not merge them.

**Existence is not asked.** The spec's error list for the receipt endpoint holds only `thread_id` faults. A
receipt may reach a server before the event does, and a client may acknowledge an event the server has
since purged, so refusing an unknown event would break honest clients for no gain. The bound on what a user
can store is the shape and the size, one row per (type, thread) key.

**The store bounds the size again.** `database::store_receipt` refuses an `event_id` or `thread_id` over 255
bytes, so a path added later cannot write an oversized row. It does not judge the shape, which belongs to
the caller that knows where the string came from.

### Consequences

* An inbound receipt with a bad event ID is ignored, not rejected: the transaction's other receipts are kept.
* A client sending `read_markers` with a bad value gets 400 and none of the body's markers is stored.

## Links

* Appendices, "Event IDs"; Client-Server API, `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}`
