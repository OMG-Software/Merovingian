# Follow Complement on client-server points the spec leaves open

* Status: accepted
* Date: 2026-10-28

Technical Story: Complement run 9 (D17); owner decision 2026-10-28

## Context and Problem Statement

Nine Complement tests encode one reading of points v1.19 leaves open. The owner chose to follow Complement on all of them, provided none contradicts the spec.

## Considered Options

* Follow Complement on each
* Skip-list them and keep current behaviour
* Decide each separately

## Decision Outcome

Chosen option: "Follow Complement on each", because each reading is spec-conformant. Oversized events answer 413 `M_TOO_LARGE` (was 400, chosen in the CSAZ-9 audit fix; the per-user filter cap stays 400 under ADR-0118). A filter upload with a field of the wrong type answers 400 `M_BAD_JSON`. Malformed `device_keys` answer `M_BAD_JSON`. `/messages` with `lazy_load_members` returns only the chunk senders' memberships. An initial `/sync` carries `m.push_rules` with the effective ruleset even if the user never changed a rule. User-directory search covers only users visible to the requester (a shared room, or a `public` or `world_readable` room), which the spec's "at a minimum" allows. A password change with `logout_devices` deletes the pushers of the revoked devices (new `pushers.device_id`).

### Positive Consequences

* Nine Complement tests stop failing on open points.

### Negative Consequences

* The directory no longer finds users who share no visible room with the searcher.
* Pushers are removed only on password change, not on logout or device deletion.

## Links

* Refines [ADR-0204](0204-keep-a-users-push-rules-as-their-m-push-rules-account-data.md)
