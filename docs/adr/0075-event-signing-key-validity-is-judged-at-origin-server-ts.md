# Event signing-key validity is judged at the event's origin_server_ts

* Status: accepted
* Date: 2026-09-28

Technical Story: finding "Key validity against `origin_server_ts`" recorded in
`docs/todos/capability-gaps.md` on the 0.12.13 branch. The option below was
chosen in writing by the user on 2026-09-28.

## Context and Problem Statement

`federation::authorize_federation_pdu` took a `now_ts` argument and rejected a
PDU when the current time was past the sender key's `valid_until_ts`, in every
room version. The backfill path passed 0, which skipped the check entirely.
The spec says something different:

* server-server-api.md, `valid_until_ts`: "This field MUST be ignored in room
  versions 1, 2, 3, and 4."
* rooms/v5.md, "Signing key validity period" (unchanged through v12):
  "servers MUST enforce the `valid_until_ts` property from a key request is at
  least as large as the `origin_server_ts` for the event being validated."
* server-server-api.md, receipt checks: "any keys that are known to have
  expired prior to the event's `origin_server_ts` are ignored."
* rooms/v5.md: "Servers MUST use the lesser of `valid_until_ts` and 7 days
  into the future when determining if a key is valid."

So the old check rejected events the spec accepts (v1-v4 with a now-expired
key, and any v5+ event older than its key's expiry), never rejected an event
sent after its key had expired, and backfill did no validity check at all. No
7-day cap was applied anywhere.

## Considered Options

* Follow the spec exactly: no current-time check; v5+ require
  `valid_until_ts >= origin_server_ts`; v1-v4 ignore `valid_until_ts`; cap a
  cached key at fetch time + 7 days.
* The spec rule plus the old current-time rejection, as an extra restriction.
* Keep the current-time rejection and add the `origin_server_ts` rule only
  where nothing was checked (backfill).

## Decision Outcome

Chosen option: "Follow the spec exactly".

* `RoomVersionPolicy::ignores_key_validity` is true for v1-v4 only. It
  defaults to false, so a version that forgets to set it enforces the check.
* `authorize_federation_pdu` has no `now_ts` parameter. For a version that
  enforces validity it rejects when `valid_until_ts < origin_server_ts`,
  including `valid_until_ts == 0` (no known validity), and rejects a PDU with
  no integer `origin_server_ts`. Every caller (`/send`, the membership and
  invite endpoints, backfill, and main's re-verification of worker relays)
  gets the same rule.
* `cache_remote_server_keys` requires the fetch time and stores
  `min(valid_until_ts, fetched_at + 7 days)`. The resolver refetches when a
  cached key reaches that time, so a key is never trusted for more than seven
  days without being fetched again.

The 7-day cap is applied at fetch time, not at check time ("7 days into the
future" from each check). The fetch-time cap is never later than the
check-time reading, and it is the one that forces a refetch, which is what
lets a key owner withdraw a key.

### Positive Consequences

* Old events signed with a since-rotated key verify, as the spec requires;
  events signed after their key expired are refused, including on backfill.

### Negative Consequences

* The removed current-time check also guarded the resolver's stale-cache
  fallback (a key served when the remote cannot be reached). That guard is now
  the 7-day cap: a stale key still verifies events sent before its capped
  expiry, and nothing sent after it.
* `origin_server_ts` is chosen by the sender, so a server holding an expired
  key can backdate events. The spec accepts this; the capped expiry bounds it.

## Pros and Cons of the Options

### Follow the spec exactly

* Good, because it is what the spec requires, in every room version.
* Bad, because a stale cached key is usable for events up to its capped
  expiry.

### The spec rule plus the current-time rejection

* Good, because a stale cached key is never used.
* Bad, because it rejects v1-v4 events on a field the spec says MUST be
  ignored, and rejects valid historical events whose key has since expired.

### Keep the current-time rejection, add the rule to backfill

* Good, because it changes the least.
* Bad, because it keeps both spec violations and applies different rules on
  different paths.

## Links

* Spec: [rooms/v5.md, "Signing key validity period"](../matrix-v1.19-spec/rooms/v5.md)
* Spec: [server-server-api.md, "Validating hashes and signatures on received events"](../matrix-v1.19-spec/server-server-api.md)
