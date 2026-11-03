# createRoom caps its invite and initial_state entries

* Status: accepted
* Date: 2026-11-02

Technical Story: security audit run-2 F-02, one createRoom stored one event per entry under `runtime.mutex`

## Context and Problem Statement

`create_room` holds `runtime.mutex` for the whole bootstrap and composes, signs, authorises and commits one event
per `invite` and `initial_state` entry. The only bound on either list was the 1 MiB body, room for tens of
thousands of entries, and the per-event work reads the room's whole state, so the lock-held work grew
quadratically in a number any registered user chooses. The spec sets no number of entries a server must accept.

## Considered Options

* Refuse past operator-configurable caps with 400 `M_TOO_LARGE` before anything is stored
* Release the lock between entries
* Store only the first N entries and ignore the rest

## Decision Outcome

Chosen option: "Refuse past operator-configurable caps", `server.client_api.max_create_room_invites` and
`max_create_room_initial_state`, default 100 each, range 1 to 10,000, as other lock-bounding caps do (ADR-0118,
ADR-0173). The raw array length is what is counted, so duplicates and non-string entries do not get past it.
Invitees are then deduplicated keeping first occurrence, because a repeated invitee has no meaning and stored a
second event.

Releasing the lock mid-bootstrap was rejected: another request could then see a half-made room, and it would not
reduce the total work. Silently dropping entries would give a client a different room from the one it asked for.

### Positive Consequences

* Lock-held work for one createRoom is bounded by a fixed count.

### Negative Consequences

* A bot that invites more than 100 users at creation has to invite the rest afterwards, or its operator raises
  the cap.
