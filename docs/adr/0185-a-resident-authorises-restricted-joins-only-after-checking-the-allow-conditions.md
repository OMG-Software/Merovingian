# A resident authorises restricted joins only after checking the allow conditions

* Status: accepted
* Date: 2026-10-21

Technical Story: conformance audit 2026-10-17, finding R04

## Context and Problem Statement

When this server is resident in a restricted (or `knock_restricted`) room, a user who is not
invited joins through an allow condition. The spec puts the check on the resident:
client-server-api.md, "Restricted rooms": "When joining without an invite, the server MUST verify
that the requesting user meets at least one of the conditions." server-server-api.md, "Restricted
rooms", names the refusals: 400 `M_UNABLE_TO_AUTHORISE_JOIN` when no condition can be validated,
400 `M_UNABLE_TO_GRANT_JOIN` when a condition holds but no local user can meet the auth rules for
`join_authorised_via_users_server`, 403 `M_FORBIDDEN` when every condition fails. The `make_join`
template must name "an arbitrary user ID belonging to the resident server ... that is able to
issue invites", and on `send_join` "the signature must be added before sending or persisting the
event". The auth rules only check that the named user is joined with invite power and that its
server signed the event (rooms/v10.md 4.2.1, 4.3.5): whether the user met a condition is checked
by nobody else.

Before 0.12.34 none of this was implemented: templates never named a user, `send_join` refused
such a join for lacking our signature, and local joins into local restricted rooms failed the
auth rules.

## Decision Outcome

One decision function, `homeserver::decide_restricted_join`, used by the `make_join` template
provider, the `send_join` acceptor and every locally composed join:

* It reads only this server's current state. A condition whose room this server holds no state
  for cannot be validated. No condition met and at least one unknown is
  `M_UNABLE_TO_AUTHORISE_JOIN`, so the joining server tries another resident; all known and none
  met is `M_FORBIDDEN`.
* At most `max_restricted_join_conditions` (32) allow entries are considered. The list is room
  state another server's administrator can write, each condition costs a lookup under
  `runtime.mutex`, and an entry past the bound counts as absent, which can only refuse.
* The authorising user is the lowest user ID among this server's joined users whose effective
  power level (room creators infinite from v12) is at least the invite level, so the same state
  always gives the same user.
* The acceptor co-signs (`sign_invite_event`, main only; the worker never signs, ADR-0078) only a
  `send_join` whose named user is ours and for which the decision is `authorised` for that named
  user, before the auth checks and before anything is stored. It refuses, unsigned and unstored,
  a join naming our user in a room that is not restricted or where the user is already invited or
  joined: our signature is not needed there and would stand as an authorisation if state
  resolution later judged the event under restricted join rules. The request layer and the worker
  relay skip the authorising-signature check only for a `send_join` naming this server
  (`PduSignatureChecks::authorised_here`), never for another endpoint or server.
* `compose_signed_event` refuses any locally composed join that names one of our users unless the
  decision is `authorised` for that user. This server signs every event it composes, so without
  this gate a client could name an administrator through `PUT /state/m.room.member` and skip the
  condition check.

### Positive Consequences

* Remote users join restricted rooms this server hosts alone; local users join local restricted
  rooms through their conditions.

### Negative Consequences

* A local user whose condition holds in a room where no local user can invite is refused (403);
  falling back to a remote join through another resident is not implemented.
* The resident does not yet send the accepted join to the room's other servers (a separate,
  pre-existing gap of the `send_join` acceptor).

## Links

* Uses [ADR-0184](0184-federation-workers-relay-make-join-to-main.md)
* Builds on [ADR-0171](0171-every-pdu-ingestion-path-verifies-the-authorising-servers-signature.md)
