# A first join into a restricted room stores the resident's verified co-signature

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement regressions after the run-2 audit fixes (1.0.2): `TestRestrictedRoomsRemoteJoin`,
`TestRestrictedRoomsRemoteJoinLocalUser`, `TestRestrictedRoomsRemoteJoinFailOver` and their MSC3787 and knock
variants.

## Context and Problem Statement

A user of this server joins a restricted room this server holds nothing of. The make_join template names
`join_authorised_via_users_server`, a user of the resident's server. Auth rule 4.3.5 of room versions 8 and later
(rooms/v10.md) allows that join only when it is signed by the authorising user's server, and
`Authorization.cpp` enforces it (EVT-1). The resident adds that signature to the copy it returns as the answer's
`event`. The send_join v2 response field is "Required if the room is restricted and the joining user is authorised by
one of the conditions".

Since F-45 (ADR-0369), `authorize_send_join_answer` checks the answer's state and auth chain against the join before
anything is stored. It was given the join this server signed itself, which has no signature from the authorising
server, so every first restricted join was refused with "the events in the answer do not authorise the join". The
resident's `event` was ignored on this path. Only a join through another resident (ADR-0287) used it.

How does this server get a join that the auth rules accept, without trusting the resident's copy?

## Decision Drivers

* A join that no checked signature authorises must never be stored (EVT-1, ADR-0171).
* The resident chooses the content of its copy. The event ID and its signatures cover the redacted form, so a resident
  could change a display name and keep both (ADR-0302).
* The same answer check must cover the first join and a join through another resident.

## Considered Options

* Take the resident's co-signature as a join through another resident does: merge only the authorising server's
  verified signatures into this server's own signed join, verify the combined event, and authorise and store that.
* Exempt this server's own join from rule 4.3.5 when it checks the answer.
* Store the resident's `event` as returned.

## Decision Outcome

Chosen option: the first. `perform_federated_join` calls `verify_resident_signed_join` whenever its join names an
authorising user. That function requires the answer's `event` to have the reference-hash ID of the join this server
signed and to name an authorising user of another server. It merges in that server's signatures only
(`with_server_signatures`), and `filter_verified_send_join_events` must verify the combined event: this server's
signature and the authorising server's. The verified combined event is what `authorize_send_join_answer` judges and
what `join_room` stores and federates. An answer with no `event`, an `event` without the authorising server's
signature, or one signed by another key is refused with 502, and nothing is stored.

### Positive Consequences

* A first restricted join works again, and the stored join carries the signature every other server's auth check
  requires.
* There is one way to accept a co-signed join, used by both join paths: `perform_federated_join` verifies, logs and
  refuses the resident's copy in one place (`verify_resident_join`), so the two paths cannot drift apart.
* The stored join's `event_signatures` rows list every signature its JSON carries, the co-signature included, so
  the rows and the event agree after a reload or in a worker's snapshot.
* The resident's template brings no `hashes` or `signatures` into the join: `claim_membership_event_template` drops
  them, because signing adds to the signatures an event holds. The signed join is parsed before it is sent and
  refused with 502 if it does not parse, so a join this server sends can always be stored with its signature rows.

### Negative Consequences

* A resident that does not return `event` for a restricted join cannot be joined through. The spec requires the field
  in this case, so such a resident is not conformant.

## Pros and Cons of the Options

### Exempt this server's own join from rule 4.3.5

* Good, because it needs no extra verification step.
* Bad, because it stores a join that no other server will accept. The join is then rejected everywhere else, and this
  server believes its user is in a room it is not in.
* Bad, because it reopens a version of the EVT-1 hole on the one path the check was meant to cover.

### Store the resident's `event` as returned

* Good, because it is the smallest change.
* Bad, because the resident could rewrite unsigned parts of the content under valid signatures (ADR-0302).

## Links

* Refines [ADR-0369](0369-a-send-join-answer-is-judged-by-the-receipt-checks-from-its-own-events.md)
* Uses [ADR-0302](0302-a-remote-signature-is-merged-into-this-servers-own-event-after-it-is-verified.md) and
  [ADR-0287](0287-a-resident-with-no-local-authoriser-joins-its-user-through-another-resident.md)
