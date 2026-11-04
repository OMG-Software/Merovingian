# A client's unsigned is built from what the server computes, and a received PDU is stored without it

* Status: accepted
* Date: 2026-11-03

Technical Story: Security audit run 2, F-70 and F-84

## Context and Problem Statement

A received PDU was stored as it arrived, `unsigned` included. `unsigned` is covered by no signature or hash (SS API "Signing events", "Calculating the reference hash for an event", "Calculating the content hash for an event": both remove `signatures` and `unsigned` first), so whichever server relayed an event chose it. The client serialisers then dropped only `transaction_id` and `membership` from the stored copy and passed on the rest, and sliding sync passed on all of it. A relaying server could give a third party's event a forged `m.relations.m.replace` bundle (the server's assertion that a replacement is valid), a `redacted_because`, a `prev_content` or an `age`, and every local client was given them as this server's own. Which rule keeps a remote server's `unsigned` from a client?

## Considered Options

* Strip `unsigned` from every received PDU before it is stored, and build a client's `unsigned` from server-computed values only
* Keep storing it and extend the serialisers' list of keys to drop
* Strip it at the store (`store_event`) for every event

## Decision Outcome

Chosen option: "Strip `unsigned` from every received PDU before it is stored, and build a client's `unsigned` from server-computed values only", because a list of keys to drop is a rule that a new `unsigned` key (or a spec revision that adds one) silently breaks, and a stored copy that is not served cannot be served by a path that forgot the list.

Two rules, each enough for the other's gap:

1. **Ingestion.** Every path that stores an event received from another server removes the top-level `unsigned` first, through `events::without_unsigned` / `events::without_unsigned_json` (`events/unsigned_data.hpp`): `parse_inbound_pdu_envelope` (so `/send`, the worker relays, the membership acceptor and the restricted-join sink), `verify_and_store_backfilled_event` (backfill, `get_missing_events`, `fetch_remote_event_into_store`), the `send_join` `state` and `auth_chain` writer, the stored `knock_room_state`, the inbound invite handler, and the `make_join`/`make_leave`/`make_knock` template this server signs (`claim_membership_event_template`). The event ID, content hash and every signature check are unchanged, because none covers `unsigned`. A PDU whose `unsigned` cannot be removed is refused, never stored with it. `invite_room_state` and `knock_room_state` come from the request's or the response's own field, never from a stored event's `unsigned`.
2. **Serving.** `client_event_with_id` and sliding sync's `client_event_json` never start from the stored `unsigned`. A client's `unsigned` holds `replaces_state` (from the state transition this server recorded), `redacted_because` (`attach_redacted_because`), and the viewer's own `transaction_id`, `membership` and `prev_content` (`sync::ViewerEventUnsigned`). This server writes no `unsigned` into a stored event, so nothing a local event needs is lost. Sliding sync applies `ViewerEventUnsigned` with the request's `HistoryVisibility` and device.

A future `unsigned` field a client should be given is added to the computed set, with the code that computes it, never by passing a stored key through.

### Positive Consequences

* A remote server cannot present metadata as this server's: `m.relations`, `redacted_because`, `prev_content`, `age`, `transaction_id`, `membership`.
* `/event`, `/backfill`, `/state` and `send_join` serve what was stored, which no longer holds a remote server's `unsigned`.
* Sliding sync now carries the viewer's `membership` and the sending device's `transaction_id`, as `/sync` does.

### Negative Consequences

* `age` is not served: no stored event holds a server-computed one, and the serving code does not compute it yet. `unsigned.age` is optional in the spec.
* Rows stored before this change keep a remote `unsigned`; rule 2 keeps it from clients, and it is still served over federation until the row is replaced.

## Pros and Cons of the Options

### Strip at ingestion and build `unsigned` at serving

* Good, because each rule covers the gap in the other
* Bad, because every new ingestion path must call the helper

### Extend the denylist

* Good, because it is the smallest change
* Bad, because the stored copy stays the source and any key not listed reaches a client

### Strip in `store_event`

* Good, because it is one place
* Bad, because the store is not told whose event it is, runs under `runtime.mutex`, and would reparse every local event

## Links

* Refines [ADR-0258](0258-unsigned-transaction-id-goes-to-the-sending-device.md): sliding sync now carries `transaction_id` for the sending device
