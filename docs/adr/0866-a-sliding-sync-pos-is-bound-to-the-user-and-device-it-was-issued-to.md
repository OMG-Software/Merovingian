# A sliding sync pos is bound to the user and device it was issued to

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4186: "Servers MUST reject a `pos` that was not issued to the requesting user and device, responding with
`M_UNKNOWN_POS`." This server's `pos` was the encoded stream position and page alone (ADR-0862), so any user could
send another's. MSC4186 and MSC4543 also let a `pos` be used as `from` / `to` in `/messages`, `/relations` and
`/keys/changes`.

## Decision Drivers

* No per-connection server memory may be needed to check a `pos`: connections are kept in memory and expire.
* The check must not tell an attacker anything about another user's `pos`.
* A `pos` must stay usable as a pagination token in the endpoints the MSCs name.

## Considered Options

* Keep a table of issued positions per user and device.
* Append a keyed hash of (label, user, device, position) to the position, and check it on every request.

## Decision Outcome

Chosen option: the keyed hash.

* `bind_sliding_sync_pos` (`SlidingSyncPosBinding.cpp`) returns `<position>-<64 hex>`, the hex being
  `crypto::generic_hash` over a domain label, the user ID, the device ID and the position, keyed with the pagination
  token key (`mutual_rooms_token_key`). The label keeps the hash from ever equalling another token's.
  `unbind_sliding_sync_pos` recomputes it and compares with `crypto::constant_time_equal_variable_length`.
* The handler binds the `pos` it answers with and unbinds the one it is sent before decoding it. A `pos` that does not
  unbind, for any reason, is 400 `M_UNKNOWN_POS` and is logged as `sliding_sync.unknown_pos` with reason
  `not issued`: one answer for a forged, altered, or other user's or device's `pos`.
* The connection state keeps the unbound position (`response_pos`), which is what a later request's position is
  matched against.
* `decode_sync_position_token` (`SlidingSyncPos.cpp`) accepts a stream token or a bound `pos` as a pagination token in
  `/messages` (`from`, `to`), `/relations` and `/keys/changes`. It does not check the hash: a pagination token is a
  position, and the reads it gates are judged by `HistoryVisibility` and the user's rooms as for any other token.
* A key that cannot be read is 500 `M_UNKNOWN` ("sliding sync positions cannot be issued"); the server never answers
  with an unbound `pos`.

### Positive Consequences

* No storage, constant-time check, and a `pos` survives a restart for as long as the key does.

### Negative Consequences

* A `pos` is 65 characters longer.
* Rotating the pagination token key ends every connection (`M_UNKNOWN_POS`, and the client starts again).

## Links

* Refines [ADR-0862](0862-a-sliding-sync-pos-carries-a-page-and-sticky-delivery-keeps-redactions-withheld-refreshes-trimmed-rooms-and-loads-sticky-senders.md)
* Same key and comparison as [ADR-0631](0631-the-mutual-rooms-token-carries-its-offset.md)
