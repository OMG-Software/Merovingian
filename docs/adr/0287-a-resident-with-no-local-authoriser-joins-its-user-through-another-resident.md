# A resident with no local authoriser joins its user through another resident

* Status: accepted
* Date: 2026-10-30

Technical Story: Complement run 12 (`TestRestrictedRoomsRemoteJoinLocalUser`,
`TestRestrictedRoomsLocalJoinNoCreatorsUsesPowerLevels`, `TestKnockRestrictedRooms...`)

## Context and Problem Statement

A local user joins a restricted or knock_restricted room this server is resident in. The user
meets an allow condition, but no joined user of this server has the power to invite, so no local
user can be named in `join_authorised_via_users_server` (rooms/v10.md 4.3.5.2).
`decide_restricted_join` answers `unable_to_grant`. Over federation the spec has the resident
answer 400 `M_UNABLE_TO_GRANT_JOIN`, "to denote that the joining server should try a different
server" (server-server-api.md "Restricted rooms"). The spec says nothing about a resident
server joining its own user. Refusing the user with 403 left a user who is entitled to join out
of the room, because a power-levels event that would have given a local user the power had not
yet reached this server, or because the room's only inviters are on another server.

## Considered Options

* Refuse the join (403), as before
* Join through another resident server with the federated join handshake (`make_join`, `send_join`)
* Compose the join here and ask another resident only for a co-signature

## Decision Outcome

Chosen option: "join through another resident server". The owner chose this where the spec is
silent. Only the `unable_to_grant` verdict takes it: the user meets a condition this server could
verify. A user who meets no condition (403), a condition this server cannot verify
(`M_UNABLE_TO_AUTHORISE_JOIN`) and a banned user are refused here as before, so the handshake
never runs for a user this server has not found entitled to join.

`decide_restricted_join` stays the only place that decides. `join_room` calls it; on
`unable_to_grant` it claims the membership exchange (ADR-0252), waits for in-flight events of the
room (ADR-0288), decides again, and only then goes remote, to at most
`max_restricted_join_fallback_candidates` (4) servers: the ones the client named first, then other
servers with joined members (`restricted_join_fallback_candidates`). The make_join race, the
signing and the `send_join` call are `perform_federated_join`, with `runtime.mutex` released.
The request lists only the room's own version. If every candidate fails the client gets the
original refusal, not an upstream error.

The handshake's result is stored as a received PDU, not as a join into a room this server has
no state for. `join_room`'s remote path (`ingest_send_join_state`, a fresh state group, retiring
the forward extremities) is built for a server that holds nothing of the room; run for a
resident it would replace state this server already holds, including events it has accepted
since. The `event` the resident returns in the `send_join` response is the join with its
co-signature ("The membership event sent to other servers by the resident server including a
signature from the resident server"). It is taken only if all of these hold, and then goes through
`federation.pdu_sink` (`ingest_pdu_event`) like any other event, with the resident as its origin
for backfill, so the auth rules judge it against this server's own state:

* its reference-hash event ID is the ID of the join this server signed (the resident did not
  change it);
* it names a `join_authorised_via_users_server` that is not a user of this server;
* `filter_verified_send_join_events` accepts it: this server's signature and the authorising
  server's signature verify (ADR-0171). Never accept a join authorised by a server whose
  signature was not checked.

`state` and `auth_chain` of the response are not read.

### Positive Consequences

* A user entitled to join a restricted room is not turned away because of a local power-level
  race or because the room's inviters live elsewhere.
* No existing room state is rewritten by the fallback.

### Negative Consequences

* The join is authorised by another server's user, so `join_authorised_via_users_server` is not
  a local user (Complement's `...NoCreatorsUsesPowerLevels` asserts a local one: the settle step
  of ADR-0288 is what keeps that test from taking this path).
* Up to four make_join calls on a refusal path, bounded and each under the usual join timeout.

## Pros and Cons of the Options

### Refuse the join

* Bad, because the user meets a condition and the room has residents who can authorise it.

### Compose the join here and ask another resident only for a co-signature

* Bad, because the spec has no endpoint to ask a resident to sign an event it did not template.
  make_join/send_join is the only exchange in which a resident co-signs.

## Links

* Builds on [ADR-0171](0171-every-pdu-ingestion-path-verifies-the-authorising-servers-signature.md) and
  [ADR-0252](0252-one-membership-exchange-per-user-and-room-at-a-time.md)
* Refined by [ADR-0288](0288-a-restricted-join-waits-for-in-flight-room-events-before-it-is-refused-or-sent-away.md)
