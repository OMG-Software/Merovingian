# unsigned.transaction_id goes to the sending device

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (C4)

## Context and Problem Statement

The spec gives `unsigned.transaction_id` "if the client being given the event is the same one which sent it", and scopes transaction IDs to a device. Our events lacked the field.

## Considered Options

* Scope it to the device that sent the event, added per request
* Scope it to the access token
* Store it in the event's `unsigned`

## Decision Outcome

Chosen option: "Scope it to the device that sent the event, added per request", because a refresh token or a login with an existing `device_id` is the same client. `client_txn_ids` records the device; `sync::ViewerEventUnsigned` adds the field only for that device, through an in-memory index by event ID so the cost is per event, not per stored transaction. Storing it on the event would sign it and send it over federation.

### Positive Consequences

* Local echo works across token refresh.

### Negative Consequences

* Idempotency is still keyed by user, not device; `/messages`, `/context`, `/relations`, `/search` and sliding sync do not carry the field yet.
* `client_txn_ids` is never pruned.
