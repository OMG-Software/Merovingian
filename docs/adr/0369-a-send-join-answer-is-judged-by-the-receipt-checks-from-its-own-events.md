# A send_join answer is judged by the receipt checks, from its own events

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-45.

## Context and Problem Statement

A resident's answer to `send_join` was filtered by room and signature and then stored as it came. A signature and an
event ID cover only the redacted form of an event, so a resident could change what redaction removes (an
`m.room.server_acl`'s whole content, for one) and keep both. The stored copy was never replaced (ADR-0285), and it was
the room's state from then on. Nothing ran the auth rules either.

The spec's receipt checks (Server-Server API, "Checks performed on receipt of a PDU") require a hash failure to redact the
event and an auth failure at step 4 to reject it. The spec does not say how to run step 4 on an answer whose events
depend on each other, or what to do with an event that cannot be judged.

## Decision Outcome

- `filter_verified_send_join_events` redacts an event whose content hash does not match, or drops it if redaction fails.
  This also covers `knock_room_state`, which goes through the same filter.
- `authorize_send_join_answer` (`send_join_answer_authorization.cpp`) judges `state` and `auth_chain` together, in
  dependency order, with `runtime.mutex` released, before anything is stored. An event is kept only if every event it
  names is kept, its `auth_events` are a permitted selection, and the rules allow it.
- An event that fails is dropped, not stored as `rejected`. A `rejected` row would answer `already_stored` for ever
  (ADR-0285), and step 5 cannot be run here.
- Only the answer's own events can authorise, never the store. Without `omit_members`, which this server never asks for
  (ADR-0241), the spec makes the answer complete. An event naming something the answer lacks is dropped.
- The join is refused with 502 when the answer's `state` holds no single valid `m.room.create`, or when the kept events do
  not allow this server's own join. `join_room` then tries the next server.

### Rejected alternatives

- **Consult the store for an auth event the answer lacks.** This needs `runtime.mutex` per lookup, for a case a
  conforming resident never produces, and it would let an old stay's rows authorise events in a room the server is
  rejoining.
- **Keep an event whose auth event failed its signature check.** This is what the code did before: an event's authority
  would be unread, which is the defect. The price is below.
- **Run the check under `runtime.mutex`, at the writer.** The cost grows with an answer a remote server chooses.
- **Recurse over `auth_events`.** The resident chooses the depth, so the walk is iterative.

### Consequences

- An intermediate event whose sender's key can no longer be fetched now takes its dependents with it. In a room with a
  long-dead administrator this can lose a large part of the state, or refuse the join when the join's own auth events are
  among the losses. Previously the join succeeded with that state silently wrong.
- A resident can still lie by omission or offer an older event in a state slot: individually valid events are not proof of
  current state. Step 5 and step 6 are not run on the answer, because this server holds no earlier state to run them on.
- The cost is linear in the answer, whose size is capped by `join_response_max_size`, with each event's map copying at most
  a few auth events.
