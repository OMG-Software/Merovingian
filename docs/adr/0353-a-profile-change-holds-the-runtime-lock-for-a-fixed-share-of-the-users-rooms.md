# A profile change holds the runtime lock for a fixed share of the user's rooms

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-11. Refines ADR-0182.

## Context and Problem Statement

`PUT /profile/{userId}/{keyName}` sends an `m.room.member` join to every room the user is a member of, one `send_event` at a
time, under the `runtime.mutex` the dispatcher already holds. Each send signs an event and commits to the database, and the
number of rooms is the user's own choice: rooms persist once created, and nothing caps them. Alternating between two display
names re-sends to every room each time, so one registered user could keep every other request waiting.

ADR-0182 already answers `200` once the field is stored and treats propagation as best effort. It says nothing about how long
the lock is held.

## Considered Options

* A request sends a fixed share, and a background job takes the lock per room for the rest
* Send everything from the job, and nothing from the request
* Release the lock between sends inside the request
* Cap the rooms a user may join

## Decision Outcome

Chosen: a fixed share, then a job. Within one hold of `runtime.mutex` a walk over `database.rooms` looks at no more than
`profile_propagation_rooms_walked_per_hold` rooms and reads no more than `profile_propagation_member_events_read_per_hold` of
the user's member events. A request sends to no more than `profile_propagation_sends_per_request` rooms, and the
`profile-propagation` job to one. All three are bounded because each is a separate cost the requester can inflate: a server's
room count, large member events in rooms already current, and database commits.

The queue (`HomeserverRuntime::profile_propagation_pending`) holds a user ID and the index to resume from:

* **No token.** The job sends through `send_event_as_user`. A bearer token is not kept in memory for it, and logging out does
  not take back a field that was validly set.
* **No event.** The profile is read in the hold that sends it, so a profile changed twice is sent once to any room not yet
  reached. A later change for the same user starts its walk again from the first room, because a room already passed holds
  the older profile; the walk skips rooms already current.
* **Membership is decided in the hold that sends.** A user who has left is not sent a join that in a public room would rejoin
  them (ADR-0182).
* **A user who is now locked, suspended or deactivated is dropped from the queue.** The request was allowed; the spec
  recommends forbidding profile changes while suspended, so what it left is not sent.

Users take turns, so that one user's rooms do not hold up another's. The job waits `profile_propagation_pace` between holds,
because the mutex does not hand over to waiters on release.

The queue is in memory. A restart or shutdown abandons it, and the job stops after at most one send. The rooms left get the
profile at the user's next change, which is what ADR-0182 already says of a room that failed. Presence is unaffected: it is
sent in the request.

`auth_events_for_room` and `current_member_content` now use the state index (ADR-0344) instead of walking the whole state
table, for every event composed on this server.

### Positive Consequences

* The lock is held for the same work whether a user has 20 rooms or 200000.
* A user in no more rooms than the request's share sees every room updated before the answer, as before.

### Negative Consequences

* A user in many rooms sees the change arrive over time, up to about 200 rooms a second across all users of the server. An
  attacker alternating names can keep the job busy, and other users' changes then wait their turn. The lock stays available
  throughout, which is what this decision protects.
* After a restart, the rooms left behind keep the older profile until the next change, with nothing in the log naming them.
* The position is an index. A failed federated join removes its room from `database.rooms`, so a walk in progress can skip one
  room, which then waits for the next change.
* The display name and avatar URL have no length limit of their own beyond the event size limit. That is a separate record in
  the audit.

## Pros and Cons of the Options

### Send everything from the job, and nothing from the request

Simple, but every profile change would be visibly delayed, for the common case of a user in a few rooms too.

### Release the lock between sends inside the request

Other requests could run, but a client request would stay open for as long as the user has rooms, holding a worker thread; a
few such requests would use up the pool instead of the lock.

### Cap the rooms a user may join

Would bound this path and no other, and would refuse legitimate use: the spec sets no limit.
