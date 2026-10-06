# Bound to-device queues by recipient count and age

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-06

Technical Story: 2026-09-29 security audit, finding CSAZ-10.

## Context and Problem Statement

The `to_device_messages` table stores pending direct-to-device deliveries for
local users. Rows are normally deleted when the target device acknowledges them
via `/sync`, but non-existent devices or abandoned clients never acknowledge
anything. Before this change the queue had no per-recipient cap and no TTL, so a
malicious or buggy sender could enqueue an unbounded number of rows for a user
or device that would never drain them. The audit required a per-recipient cap
and age-based eviction.

## Decision Drivers

* Memory and disk must not grow without bound because of undeliverable rows.
* A legitimate user with many devices must not have one device's queue affect
  another device.
* Acknowledged rows must still be deleted on schedule; the TTL is a safety net,
  not a replacement for acknowledgement.
* Existing rows loaded from older schema versions must keep working (the new
  column has a default value).

## Considered Options

1. Cap the total number of rows in `to_device_messages` globally.
2. Cap the number of rows per `target_user_id`, sharing one cap across all of
   the user's devices and wildcard (`*`) broadcasts.
3. Cap the number of rows per `(target_user_id, target_device_id)` pair, and
   apply the same TTL to every row.

## Decision Outcome

Chosen option: "per-(user, device) cap with a per-row TTL", because it is the
finest grained bound that still treats wildcard broadcasts as a single
recipient. A global cap would let one noisy sender starve every other recipient;
a per-user cap would let one device consume the whole user's budget. The per-row
TTL removes stale broadcasts and abandoned targeted rows even when no new
messages arrive for that recipient.

The cap and TTL are configured in `server.client_api` and copied into
`PersistentStore` at runtime startup, so the database layer can enforce them
without depending on the config module. `enqueue_to_device_message` evicts
expired rows first, then the oldest rows, before inserting the new row. The
whole eviction+insertion is committed as one transaction, so a failed durable
write leaves the in-memory mirror unchanged. `drain_to_device_messages` also
purges TTL-expired rows when a device syncs, so old state does not sit
indefinitely for recipients that only occasionally connect.

### Positive Consequences

* The queue cannot grow without bound for non-existent or abandoned devices.
* Broadcast (`*`) rows share one per-user broadcast cap, while device-targeted
  rows are isolated per device.
* The schema change is backward-compatible: existing rows get `created_at_ms=0`
  and are eligible for immediate TTL-based eviction, which is the desired
  behaviour for stale rows.

### Negative Consequences

* Eviction is currently done inline on enqueue and drain. A very large backlog
  could make a single enqueue slow; however the cap prevents the backlog from
  becoming "very large" in the first place.
* Rows with `created_at_ms=0` from the migration are treated as immediately
  expired if TTL is enabled. This is intentional, but it means a long-lived
  upgrade may silently discard genuinely pending rows that predate the column.

## Pros and Cons of the Options

### Global cap

* Good, because it is simple to implement and reason about.
* Bad, because one noisy sender can evict every other recipient's messages.

### Per-user cap

* Good, because it isolates users from each other.
* Bad, because one device can consume the entire user's budget and starve other
  devices of the same user.

### Per-(user, device) cap with per-row TTL

* Good, because it isolates each device and each broadcast scope.
* Good, because the TTL removes rows for recipients that never sync.
* Bad, because it requires matching `(user_id, device_id)` on every enqueue and
  drain, and adding a new indexed column.
