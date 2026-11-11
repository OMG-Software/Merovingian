# A join naming another user is refused at receipt, and the auth rule stays as the spec writes it

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `F-events.authorization.creator-bootstrap-join-ignores-sender` and
`F-chain.history-read.forged-creator-join-lifts-departure-limit`.

## Context and Problem Statement

The auth rules for `m.room.member` with `membership` `join` begin: if the only previous event is the `m.room.create` and
the `state_key` is the creator, allow (`docs/matrix-v1.19-spec/rooms/v10.md`, and v11 and v12). The check that `sender`
matches `state_key` comes after it. So any server can write a join for a room's creator, citing only the create event,
that passes the auth rules with a sender of its own. Stored, it put the creator back in the room, lifted the limit on
what a departed user may read, and could take current state.

Where is it refused, given that the rule is the spec's?

## Decision Drivers

* `authorize_event_against_auth_events` is the consensus rule. State resolution re-runs it, and every server must reach the
  same answer for the same events.
* `tests/conformance/test_security_audit_evt_7.cpp` pins the rule as written.
* No honest server produces such an event: a join is always sent by the user joining.
* Rejecting an event is a local decision the spec already allows; a server need not accept what it receives.

## Considered Options

* Add the sender check ahead of the bootstrap clause in the auth rules.
* Refuse the event at receipt, as one pure function called at every place a remote event is admitted.

## Decision Outcome

Chosen option: "Refuse the event at receipt".

* `events::join_names_another_user` is true for `m.room.member`, `membership` `join`, with a string `sender` and a string
  `state_key` that differ. It is the one definition.
* `ingest_pdu_event` and `verify_and_store_backfilled_event` run it after the auth rules and store a match as `rejected`,
  the disposition of an event that fails them, so its after-state is its state before and an event citing it behaves as
  one citing any rejected event.
* The membership acceptor answers `403` and stores nothing, as for any event it would reject.
  `authorize_send_join_answer` drops a match from a resident's `send_join` answer, as it drops anything the auth rules
  refuse.
* Changing the auth rule was rejected. The state a resolution computes would then differ from every other server's for
  a room holding such an event, and a room would split on a rule that is not in the spec.

### Positive Consequences

* A forged creator join changes nothing on this server, on any path that admits a remote event.

### Negative Consequences

* A room whose history really does hold such an event, accepted by other servers, has that event rejected here. Its
  descendants are judged as for any rejected event, which can leave this server's view different from theirs. Such a
  history can only come from a server forging it.
* Inside state resolution the auth rule still allows the event, so a new path that admits events without this check
  would admit it. `src/homeserver/AGENTS.md` lists the rule.
