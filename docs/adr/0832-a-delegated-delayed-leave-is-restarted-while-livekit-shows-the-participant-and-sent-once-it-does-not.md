# A delegated delayed leave is restarted while LiveKit shows the participant, and sent once it does not

* Status: accepted
* Date: 2026-11-17

Technical Story: MatrixRTC slice 4. The owner chose to implement MSC4195's optional delegated delayed leave.

## Context and Problem Statement

A MatrixRTC client schedules a delayed `m.rtc.member` leave (MSC4140, ADR-0823) and restarts it while it is in the
call, so its membership ends if it vanishes. MSC4195 lets the client hand that work to its homeserver:
`POST /_matrix/client/v1/rtc/livekit/delegate_delayed_leave` with `{url, room_id, slot_id, member_id, delay_id}`. The
server then restarts the event while the LiveKit participant is connected and sends it once the participant has
disconnected. The client, believing the server has the event, stops restarting it and uses a long delay (Element Call
uses one hour).

What the server does with a delegation decides whether a user's call membership is ended at the right time. Two
failures matter: ending a membership while the user is still in the call, and keeping one alive after they have left.

## Decision Drivers

* A delegation acts only on a delayed event the delegating user owns, in the room they named, while they are joined.
* No input the server cannot verify ends or prolongs a membership by itself.
* When the server cannot tell, the event falls back to its own timer, which is where the client left it.
* A restart of this server does not drop delegations, so a connected participant is not ended an hour later.

## Decision Outcome

### The request

`POST /_matrix/client/v1/rtc/livekit/delegate_delayed_leave` and the unstable
`/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave`, with an access token and the account
gate. In order:

1. The built-in token service off: 404 `M_UNRECOGNIZED`.
2. A body that is not the five strings, within the get_token bounds (`delay_id` at most 64 bytes): 400.
3. `url` not `server.rtc.livekit.url` byte for byte: 400 `M_INVALID_PARAM` (MSC4195 MUST).
4. The caller's current membership not `join`: 403 `M_FORBIDDEN`, as get_token answers.
5. The delayed event not the caller's, not in `room_id`, or not scheduled: 400 `M_INVALID_PARAM`, one answer for all
   three (MSC4195 MUST), so a delay ID of another user's is not confirmed.
6. Its delay under 5 minutes: 400 `M_INVALID_PARAM` (MSC4195 MAY). A shorter delay would need a restart more often than
   LiveKit is polled.
7. The user holding 20 delegations already, none of them for this key: 429 `M_LIMIT_EXCEEDED`, nothing evicted.

Then the delegation is stored, replacing any of the same (user, room, slot, member) and any of the same delay ID
(MSC4195 MUST: one per key), and the answer is `{}`. The route is limited per user (30 a minute).

### Stored, so a restart keeps it

Delegations are rows of `livekit_delegations` (migration 004): the delay ID, user, room, slot, member and creation time.
Nothing else about a delegation needs to survive a restart: after one, every delegation is checked again from the
start.

### LiveKit decides, by polling

A job in the main process, `livekit-delegations`, checks each delegation about every 30 seconds with LiveKit's
`GetParticipant` for the delegation's room name and identity (MSC4195 names, ADR-0829), at most 16 calls a run, with
`runtime.mutex` released for the calls (ADR-0830). Under the lock, before any call, a delegation is dropped (its row
deleted, the event left as it is), at most 64 a run so that one lock hold stays bounded (each drop is a commit, and
erasing from the in-memory table costs its size; the rest go on the next run, soon after), when:

* its delayed event is no longer scheduled (sent, cancelled or failed);
* the user is no longer joined to the room;
* the token service is no longer configured.

After a call, under the lock again, an answer is applied only to the delegation it was asked for: the same delay ID,
user, room, slot, member and creation time, with the same LiveKit room name and identity. A delegation stored again
while the lock was free (another member for the same delay ID, say) is a different participant, and the answer is
dropped rather than recorded as seeing it.

A run asks the due delegations most overdue first, so with more than 16 due none waits behind the others for ever.
Each call's token is stamped with the clock when that call is made, not when the run began, so a run made slow by
LiveKit never sends a token that is about to expire. A checked delegation's next check is 30 seconds after the run's
calls ended, not after it began: a run that took as long as the interval would otherwise find the same 16 due again,
and ask them again, while the rest waited.

After a call:

* **Connected** (an answer for the participant in a state other than `DISCONNECTED`): recorded. If less than half the
  delay remains, the event is restarted through `manage_delayed_event`.
* **Gone** (Twirp `not_found`, or the participant `DISCONNECTED`): if the participant was seen connected, or the
  delegation is more than 2 minutes old, the event is sent through `manage_delayed_event` and the delegation dropped.
  A delegation younger than that is left to wait, for a client still connecting.
* **Unknown** (LiveKit unreachable, a timeout, any other answer): nothing changes.

The event is restarted only on a "connected" answer to the call just made, never on one remembered from an earlier
run. When LiveKit cannot be asked, the restarts stop and the event is sent by its own timer: a lost LiveKit ends
memberships late, never early.

Both actions go through `manage_delayed_event`, as the user's own `restart` and `send` would, so a send is authorised
against the room when it happens (ADR-0825) and an account refusal applies.

### Webhooks only prompt a check

LiveKit's `participant_joined`, `participant_left` and `participant_connection_aborted` webhooks (ADR-0833) mark the
matching delegation to be checked at the next run and wake the job. A webhook never restarts or sends an event itself,
so a webhook that is replayed, reordered or lost changes when a check happens, never its outcome.

### Positive Consequences

* A participant who drops off the SFU leaves the call within about 30 seconds, or at once when the webhook arrives,
  instead of after the client's delay.
* A delegation that can no longer be acted on safely falls back to the behaviour the client chose.

### Negative Consequences

* While the server is down, or LiveKit cannot be asked, a vanished participant stays listed until the event's own delay
  runs out (an hour for Element Call).
* One `GetParticipant` call per delegation every 30 seconds.
* Delegation works only for this server's SFU, as MSC4195 says.

## Pros and Cons of the Options

### Act on the webhook alone

* Good, because it is immediate and makes no calls.
* Bad, because LiveKit's webhooks are delivered at most a few times with no guarantee; a lost `participant_left` keeps a
  membership alive for as long as the server goes on restarting it.

### Keep delegations in memory only

* Good, because it needs no migration.
* Bad, because after a restart nothing restarts the delegated events, and every participant still connected is ended
  when the client's hour runs out.

### Send the leave whenever LiveKit cannot be asked

* Good, because a vanished participant never lingers.
* Bad, because a LiveKit outage or a slow answer would end every call membership on the server.

## Links

* Refines [ADR-0829](0829-the-built-in-livekit-token-service-issues-tokens-only-to-users-this-server-finds-joined.md)
* [ADR-0825](0825-a-due-delayed-event-is-sent-by-one-job-through-the-ordinary-send-path-never-early-and-at-least-once.md)
* [ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md)
* [ADR-0830](0830-every-call-to-livekit-goes-to-the-configured-address-with-a-token-of-its-own.md)
* [ADR-0833](0833-the-livekit-webhook-is-served-on-the-client-listener-and-trusted-only-to-prompt-a-check.md)
