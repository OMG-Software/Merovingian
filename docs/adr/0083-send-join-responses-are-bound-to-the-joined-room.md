# send_join responses are bound to the joined room; own-domain events are always signature-checked

* Status: accepted
* Date: 2026-09-29

Technical Story: finding FED-1 (critical) in
`docs/security-audit-report-2026-09-29.md`.

## Context and Problem Statement

When a local user joins a remote room, `join_room` stores the resident
server's `send_join` response: the `state` array (the room state before the
join) and the `auth_chain`. Three things about that ingestion let a local user
who controls a remote server rewrite the state of any room hosted here:

1. Nothing checked that an event in `state` or `auth_chain` belonged to the
   room being joined. `ingest_send_join_state` stored each event under its own
   `room_id` and wrote it to that room's `current_state`.
2. `filter_verified_send_join_events` kept every event whose sender was on our
   own server without any signature check ("self-signed, we hold that key").
   An unsigned `m.room.power_levels` naming a local sender passed.
3. The auth-chain loop wrote each auth-chain event to `current_state` too,
   although those events are historical ancestors (outliers), not the room's
   state.

The spec is plain on (2): "Checks performed on receipt of a PDU … 2. Passes
signature checks, otherwise it is dropped." It has no exception for events
that name the receiving server. On (1), "Joining Rooms" defines `state` and
`auth_chain` as the state and auth chain of the room being joined. How the
server enforces that, and how it checks an own-domain event, are decisions.

## Considered Options

* Keep trusting own-domain events; only add the room binding.
* Verify own-domain events against this server's own signing keys, read from
  the persisted key rows it generated (current and retired); bind every entry
  to the joined room before verification and again at the writer; store
  auth-chain events with no `current_state` row.
* Verify own-domain events through `remote_key_resolver` like any other
  domain (fetch our own `/_matrix/key/v2/server`).
* Drop every own-domain event in a `send_join` response outright.

## Decision Outcome

Chosen option: the second.

* **Room binding, twice.** `filter_send_join_events_for_room` drops every
  `state` and `auth_chain` entry whose `room_id` is not the room being joined,
  before any key resolution, on both the synchronous and the background
  (partial-state) path. Under v12, where `m.room.create` has no `room_id`, the
  create event belongs only when `"!"` + its reference-hash event ID equals the
  joined room ID; a v12 create event that carries a `room_id` is dropped (v12
  auth rule 1.2 rejects it). `ingest_send_join_state` takes the joined room ID
  and repeats the check, so the writer itself can never touch another room.
  The `event` field of the `send_join` response is not consumed at all; the
  join event we store is the one we signed from the validated `make_join`
  template, whose `room_id` must equal the requested room.
* **Own-domain events are verified against our own keys.** The key is looked
  up by the signature's key ID among the `server_signing_keys` rows for our
  server name that hold a secret — rows this server generated, the same set
  published as `verify_keys` and `old_verify_keys`. A row without a secret is
  a copy fetched from somewhere and is not trusted as ours. The ADR-0075
  validity rule applies as for any key. A key ID we do not hold, or a
  signature that does not verify, drops the event.
* **Our own key rows cannot be replaced from outside.** Because own-domain
  verification trusts those rows, the remote-key resolver never fetches or
  caches keys for our own server name; it answers that name only from the
  same secret-holding rows (`federation::find_own_server_signing_key`). And
  `store_server_signing_key` refuses a write without a secret that would
  change the public key of a row holding one; retiring a key (same public
  key, new `valid_until_ts`) still works. The guard is in C++, before the
  upsert, so it does not depend on how a backend stores `secret_key`.
* **Auth-chain events never become current state.** They are stored as
  outliers with no `current_state` row, and `repair_missing_state_entries`
  only promotes events whose status is `accepted`, so a restart cannot turn an
  outlier (or a rejected event) into current state either.

Rejected alternatives:

* *Keep the own-domain shortcut.* It looks like a free optimisation — "we hold
  that key" — but the shortcut never used the key; it accepted anything that
  named our domain, which is exactly what FED-1 exploited. A resident server
  has no reason to send us events we authored that we cannot verify.
* *Resolve our own keys over the network.* Discovery of our own server name
  goes through DNS and `.well-known`, which an attacker may influence, and the
  answer would be cached into the same rows as our real keys. We already hold
  the authoritative public keys locally.
* *Drop own-domain events outright.* A re-join legitimately receives our own
  users' earlier membership events back in `state`; dropping them would leave
  the joined room's state incomplete.

### Positive Consequences

* A `send_join` response can only ever write the joined room's state, and
  only with events whose signatures verify.
* Legitimate re-joins still accept our own users' events.

### Negative Consequences

* An own-domain event signed with a key this server has since deleted from
  `server_signing_keys` is dropped. Keys are retired, not deleted, so this
  only affects a server whose key rows were removed by hand.
* Auth-chain-only state events have no `state_transitions` row, so
  `unsigned.replaces_state` cannot name one of them as a predecessor.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
  (outlier status for `send_join` events).
* Same principle as [ADR-0070](0070-event-auth-outliers-carry-no-state.md):
  an event verified only as an ancestor carries no state.
* Relies on [ADR-0075](0075-event-signing-key-validity-is-judged-at-origin-server-ts.md)
  (key validity at `origin_server_ts`).
