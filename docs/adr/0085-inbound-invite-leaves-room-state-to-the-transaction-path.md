# An inbound invite for a room we hold leaves room state to the transaction path

* Status: accepted
* Date: 2026-09-29

Technical Story: security audit 2026-09-29, finding FED-5, and FED-7 for the
second decision below.

## Context and Problem Statement

`PUT /_matrix/federation/v{1,2}/invite/{roomId}/{eventId}` used to rewrite the
invitee's membership row and store the remote event as the invitee's current
`m.room.member` state. For a room this server hosts, that let any remote server
replace a `ban` with an `invite`. The spec says the endpoint's event is
delivered a second time, through a federation transaction, when the remote server
is already in the room. Which of the two deliveries should change room state, and
what should the endpoint store?

A second, smaller decision came with the device-list fix: how to stop a peer
growing `device_list_changes` by repeating an EDU.

## Considered Options

* Authorise the invite, then keep writing it into `current_state` and the event
  graph as before.
* Authorise the invite and write nothing but the invitee's membership row and
  invite metadata, for a room whose state we hold (chosen).
* Authorise the invite and store it as an `outlier` event without a state row.

For `device_list_changes`:

* A unique index on `(observer_user_id, subject_user_id)`, which needs migration 018 and a
  de-duplication step in the migration.
* Replace the pair's earlier row in the same transaction (chosen).

## Decision Outcome

For a room whose create event we hold, `invite_handler` authorises the event
against the room's current state (403 `M_FORBIDDEN` on failure), never replaces a
`ban`, and stores neither the event nor a state row. The transaction copy is what
updates state, and it does the full PDU checks.

Storing the event as an outlier looks harmless, and is what the unknown-room
branch still does, but the store refuses an event ID it already holds
(`prepare_store_event_with_state`), so the transaction copy would fail to
persist and never reach state handling. So the endpoint must not store the event
for a room we hold. Do not "fix" this by
storing it for the send_join auth chain: for a room we hold, the transaction copy
supplies it.

`device_list_changes` keeps one row per `(observer, subject)` by replacing the
earlier row (a `DELETE` then an `INSERT`, one transaction). This avoids a
migration and keeps `/sync` correct, since a row must carry the newest stream
position for a client whose since token lies between two changes. A unique index
would not do that on its own (a duplicate insert would fail rather than move the
row) and would have had to be applied to databases that already hold duplicates.

### Negative Consequences

* Until the transaction copy arrives, the invitee cannot join an invite-only room we
  host from this server, because their join is authorised against state that lacks the
  invite. That is the spec's ordering.

## Links

* `docs/threat-model.md`, "Federation EDU identity, invite authorisation and device-list fan-out"
