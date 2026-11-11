# The to-device queue has standing indexes and a per-user limit

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, whole-table scans of to-device and key rows under the runtime mutex

## Context and Problem Statement

Every `/sync` drain, `PUT /sendToDevice` and inbound `m.direct_to_device` walked every queued to-device row on the server
(ADR-0336 made it one pass, not none), and the one-time and fallback key counts of `/sync` walked those tables too.
Nothing bounded the queues of one user across devices: a user with 200 devices holds 200 per-device budgets.

## Decision Drivers

* The work under `runtime.mutex` must not grow with other users' queues.
* The rules of ADR-0335 stay: the byte total is computed from the rows, never kept as a counter that can drift.
* Oldest rows are evicted first, never the incoming message (ADR-0117).

## Considered Options

* Keep ADR-0336's one pass per batch
* Standing `RowGroupIndex` indexes by (user, device) and by user, trusted only while in step
* Refuse a message past the per-user limit instead of evicting

## Decision Outcome

Chosen option: "Standing `RowGroupIndex` indexes by (user, device) and by user, trusted only while in step".

`to_device_recipient_index` and `to_device_user_index` follow ADR-0603: used only while built for the vector's row count, a
writer heals a stale one and a reader scans. This replaces ADR-0336's rejection of a standing index, which was right
before `RowGroupIndex` existed: the risk it named, a stale index that silently loses rows, is what the trust rule removes.
The rest of ADR-0336 stands. An erase moves the last row into the gap, so `to_device_messages` has no meaningful order;
readers sort what they return.

A send gathers the rows of the users it names through the per-user index, so the work is those users' own rows, bounded by
the limits. `server.client_api.max_to_device_messages_per_user` (50000) and `max_to_device_bytes_per_user` (64 MiB) bound
all of a user's queues; past either, the user's oldest row goes first, whichever device holds it. `/sync` reads the
device's queue and the two broadcast queues, and the key counts read `one_time_key_device_index` and
`fallback_key_device_index`.

### Rejected: keeping a byte counter per user

ADR-0335 rejected a counter because it can drift after an eviction, a failed commit or hydration. A send walks the
recipient user's rows instead, at most the per-user limit.

### Rejected: refusing past the limit

A sender would then be able to tell how full a user's queue is, and a stale device's backlog would block room keys to the
user's live devices.

### Negative Consequences

* A send to a user with a full queue reads up to that user's limit of rows.
* A user's forgotten device can lose rows to a busy one, and the reverse, once the user is at the limit.
